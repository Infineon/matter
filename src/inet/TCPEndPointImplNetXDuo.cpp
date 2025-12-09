/*
 *
 *    Copyright (c) 2020-2021 Project CHIP Authors
 *    Copyright (c) 2024 Infineon Technologies, Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 * This file implements Inet::TCPEndPoint using NetXDuo.
 */

#include <inet/TCPEndPointImplNetXDuo.h>

#include <inet/InetFaultInjection.h>
#include <inet/arpa-inet-compatibility.h>

#include <lib/support/CodeUtils.h>
#include <lib/support/SafeInt.h>
#include <lib/support/logging/CHIPLogging.h>
#include <system/SystemFaultInjection.h>

#include <stdio.h>
#include <string.h>
#include <utility>

#include <nx_api.h>

#ifndef NX_TCP_WINDOW_SIZE
#define NX_TCP_WINDOW_SIZE      (7 * 1024)
#endif

namespace chip {
namespace Inet {

/**
 * @brief   Return the NetXDuo IP instance for a specified address
 */
NX_IP * Get_NetXDuo_IP_By_Addr(NXD_ADDRESS addr)
{
    NX_IP *ret_ip = NULL;

    /*
     * Traverse the created IP list and find the one associated with this address
     * Disable interrupts while traversing the list to prevent it being modified while
     * in use.
     */

    TX_INTERRUPT_SAVE_AREA
    ULONG i = 0;

    TX_DISABLE
    for (NX_IP * ip = _nx_ip_created_ptr; i++ < _nx_ip_created_count; ip = ip->nx_ip_created_next)
    {
        for (int j = 0; j < NX_MAX_IP_INTERFACES; j++)
        {
            NX_INTERFACE * intr = &ip->nx_ip_interface[j];
            if (intr->nx_interface_valid && intr->nx_interface_link_up)
            {
                /*
                 * Check to see if we have an address match.
                 */

                if (addr.nxd_ip_version == NX_IP_VERSION_V4)
                {
                    if (intr->nx_interface_ip_address == addr.nxd_ip_address.v4)
                    {
                        ret_ip = ip;
                        break;
                    }
                }
                else
                {
                    NXD_IPV6_ADDRESS * ipv6_addr = intr->nxd_interface_ipv6_address_list_head;
                    while (ipv6_addr != nullptr)
                    {
                        if (ipv6_addr->nxd_ipv6_address_valid)
                        {
                            if (ipv6_addr->nxd_ipv6_address[0] == addr.nxd_ip_address.v6[0] &&
                                ipv6_addr->nxd_ipv6_address[1] == addr.nxd_ip_address.v6[1] &&
                                ipv6_addr->nxd_ipv6_address[2] == addr.nxd_ip_address.v6[2] &&
                                ipv6_addr->nxd_ipv6_address[3] == addr.nxd_ip_address.v6[3])
                            {
                                ret_ip = ip;
                                break;
                            }
                        }
                        ipv6_addr = ipv6_addr->nxd_ipv6_address_next;
                    }
                }
            }
        }
    }
    /* Restore previous interrupt posture.  */
    TX_RESTORE

    return ret_ip;
}

CHIP_ERROR TCPEndPointImplNetXDuo::BindImpl(IPAddressType addrType, const IPAddress & addr, uint16_t port, bool reuseAddr)
{
    NXD_ADDRESS ipAddr;
    CHIP_ERROR res = addr.ToNetXDuoAddr(addrType, ipAddr);

    if (res == CHIP_NO_ERROR)
    {
        /*
         * The socket needs to be associated with an IP instance. Search for
         * an IP instance for the bind address.
         */

        NX_IP * ip = Get_NetXDuo_IP_By_Addr(ipAddr);
        res = GetSocket(ip);
    }

    if (res == CHIP_NO_ERROR)
    {
        /*
         * TCP server sockets get bound as part of the listen call. TCP client sockets
         * use a different API to bind the socket. Since we don't know whether we're
         * a client or server socket at this point, just record the port number to use.
         */

        mBoundPort = port;
    }

    return res;
}

CHIP_ERROR TCPEndPointImplNetXDuo::ListenImpl(uint16_t backlog)
{
    // Start listening for incoming connections.
    // NetXDuoHandleIncomingConnection will be invoked when a connection request is received.
    UINT status;
    CHIP_ERROR res = CHIP_NO_ERROR;
    status = nx_tcp_server_socket_listen(mTCP->nx_tcp_socket_ip_ptr, mBoundPort, mTCP, backlog, NetXDuoHandleIncomingConnection);
    if (status != NX_SUCCESS)
    {
        res = chip::System::MapErrorNetXDuo(status);
        return res;
    }
    mNetXDuoEndPointType = NetXDuoEndPointType::TCP;

    return res;
}

CHIP_ERROR TCPEndPointImplNetXDuo::ConnectImpl(const IPAddress & addr, uint16_t port, InterfaceId intfId)
{
    CHIP_ERROR res = CHIP_NO_ERROR;
    UINT status = NX_SUCCESS;
    NX_INTERFACE * nx_interface;
    NX_IP * ip;

    res = intfId.GetNetXDuoInterfaceIP(ip, nx_interface);

    if (res == CHIP_NO_ERROR)
    {
        res = GetSocket(ip);
    }

    if (res == CHIP_NO_ERROR)
    {
        /*
         * NetXDuo requires that a socket be bound to a port before connecting. If that
         * hasn't been done, do it now.
         */

        if (!mTCP->nx_tcp_socket_bound_next)
        {
            if ((status = nx_tcp_client_socket_bind(mTCP, NX_ANY_PORT, TX_NO_WAIT)) != NX_SUCCESS)
            {
                res = chip::System::MapErrorNetXDuo(status);
            }
        }
    }

    if (res == CHIP_NO_ERROR)
    {
        /*
         * Make sure we have a callback for handshake completion.
         * Note: H1 CP doesn't have support for the establish notify callback in its NetXDuo
         * configuration. And the establish notify callback only handles the successful
         * handshake completion. It does not provide notification of error conditions. The
         * NetXDuo BSD layer uses a separate thread to monitor the socket state to detect if
         * the connect attempt fails.
         *
         * Until we have an environment to address these issues, use a blocking connect call.
         */

        status = nx_tcp_socket_establish_notify(mTCP, NetXDuoHandleConnectComplete);
        if ( status != NX_SUCCESS)
        {
           res = chip::System::MapErrorNetXDuo(status);
        } 
        NXD_ADDRESS nxdAddr = addr.ToNetXDuoAddr();
        ULONG wait = (ULONG)(mConnectTimeoutMsecs * TX_TIMER_TICKS_PER_SECOND / 1000);
        if (wait == 0)
        {
            wait = 3 * NX_IP_PERIODIC_RATE;
        }
        if ((status = nxd_tcp_client_socket_connect(mTCP, &nxdAddr, port, wait)) != NX_SUCCESS)
        {
           res = chip::System::MapErrorNetXDuo(status);
        }
    }

    if (res == CHIP_NO_ERROR)
    {
        mState = State::kConnecting;
        Retain();

        // Senice we are connected at this point, post callback to HandleConnectComplete.
        Retain();
        CHIP_ERROR err = GetSystemLayer().ScheduleLambda([this, conErr = CHIP_NO_ERROR] {
            HandleConnectComplete(conErr);
            Release();
        });
        if (err != CHIP_NO_ERROR)
        {
            Release();
        }
   }
   return res;
}

CHIP_ERROR TCPEndPointImplNetXDuo::GetPeerInfo(IPAddress * retAddr, uint16_t * retPort) const
{
    UINT status = NX_SUCCESS;
    VerifyOrReturnError(IsConnected(), CHIP_ERROR_INCORRECT_STATE);

    CHIP_ERROR res = CHIP_ERROR_CONNECTION_ABORTED;
    if (mTCP != nullptr)
    {
        NXD_ADDRESS peerAddr;
        ULONG peerPort;
        UINT status;

        status = nxd_tcp_socket_peer_info_get(mTCP, &peerAddr, &peerPort);
        if (status == NX_SUCCESS)
        {
            *retPort = (uint16_t)peerPort;
            *retAddr = IPAddress(peerAddr);
            res      = CHIP_NO_ERROR;
        }
        else
        {
           res = chip::System::MapErrorNetXDuo(status);
        }
    }

    return res;
}

CHIP_ERROR TCPEndPointImplNetXDuo::GetLocalInfo(IPAddress * retAddr, uint16_t * retPort) const
{
    VerifyOrReturnError(IsConnected(), CHIP_ERROR_INCORRECT_STATE);

    CHIP_ERROR res = CHIP_ERROR_CONNECTION_ABORTED;
    if (mTCP != nullptr)
    {
        TX_INTERRUPT_SAVE_AREA

        /* Lockout interrupts.  */
        TX_DISABLE

        *retPort = static_cast<uint16_t>(mTCP->nx_tcp_socket_port);

#if INET_CONFIG_ENABLE_IPV4 && !NX_DISABLE_IPV4
        if (mTCP->nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V4)
        {
            *retAddr = IPAddress(mTCP->nx_tcp_socket_connect_interface->nx_interface_ip_address);
        }
#endif
#ifdef FEATURE_NX_IPV6
        if (mTCP->nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V6)
        {
            *retAddr = IPAddress(mTCP->nx_tcp_socket_ipv6_addr->nxd_ipv6_address);
        }
#endif
        /* Restore interrupts.  */
        TX_RESTORE

        res = CHIP_NO_ERROR;
    }

    return res;
}

CHIP_ERROR TCPEndPointImplNetXDuo::GetInterfaceId(InterfaceId * retInterface)
{
    VerifyOrReturnError(IsConnected(), CHIP_ERROR_INCORRECT_STATE);

    CHIP_ERROR res = CHIP_ERROR_CONNECTION_ABORTED;
    if (mTCP != nullptr)
    {
        /*
        * Traverse the created IP list and find the one associated with this socket. Then
        * we can derive the interface id from the interface index.
        * Disable interrupts while traversing the list to prevent it being modified while
        * in use.
        */

        TX_INTERRUPT_SAVE_AREA
        NX_IP *ip;
        ULONG i = 0;
        int id;

        TX_DISABLE
        for (ip = _nx_ip_created_ptr; i < _nx_ip_created_count; ip = ip->nx_ip_created_next, i++)
        {
            if (mTCP->nx_tcp_socket_ip_ptr == ip)
            {
                break;
            }
        }

        if (i < _nx_ip_created_count)
        {
            // Calculate the interface id. Valid Ids start at 1.
            id = (i * NX_MAX_IP_INTERFACES) + 1 + mTCP->nx_tcp_socket_connect_interface->nx_interface_index;
            res = CHIP_NO_ERROR;
        }
        /* Restore previous interrupt posture.  */
        TX_RESTORE

        if (res == CHIP_NO_ERROR)
        {
            *retInterface = InterfaceId(id);
        }
    }

    return res;
}

CHIP_ERROR TCPEndPointImplNetXDuo::SendQueuedImpl(bool queueWasEmpty)
{
#if INET_CONFIG_OVERRIDE_SYSTEM_TCP_USER_TIMEOUT
    if (!mUserTimeoutTimerRunning)
    {
        // Timer was not running before this send. So, start
        // the timer.
        StartTCPUserTimeoutTimer();
    }
#endif // INET_CONFIG_OVERRIDE_SYSTEM_TCP_USER_TIMEOUT
    return CHIP_NO_ERROR;
}

CHIP_ERROR TCPEndPointImplNetXDuo::EnableNoDelay()
{
    VerifyOrReturnError(IsConnected(), CHIP_ERROR_INCORRECT_STATE);

    // NetXDuo doesn't have support for Nagle's Algorithm
    return CHIP_NO_ERROR;
}

CHIP_ERROR TCPEndPointImplNetXDuo::EnableKeepAlive(uint16_t interval, uint16_t timeoutCount)
{
    VerifyOrReturnError(IsConnected(), CHIP_ERROR_INCORRECT_STATE);

    /*
     * NetXDuo keepalive behavior is defined at compile time.
     */

    return CHIP_ERROR_NOT_IMPLEMENTED;
}

CHIP_ERROR TCPEndPointImplNetXDuo::DisableKeepAlive()
{
    VerifyOrReturnError(IsConnected(), CHIP_ERROR_INCORRECT_STATE);

    /*
     * NetXDuo keepalive behavior is defined at compile time.
     */

    return CHIP_ERROR_NOT_IMPLEMENTED;
}

CHIP_ERROR TCPEndPointImplNetXDuo::SetUserTimeoutImpl(uint32_t userTimeoutMillis)
{
    return CHIP_ERROR_NOT_IMPLEMENTED;
}

CHIP_ERROR TCPEndPointImplNetXDuo::DriveSendingImpl()
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    // If the connection hasn't been aborted ...
    if (mTCP != NULL)
    {
        while (!mSendQueue.IsNull())
        {
            NX_PACKET * packet = reinterpret_cast<NX_PACKET *>(mSendQueue.PopHeadBuffer());
            ptrdiff_t len = packet->nx_packet_append_ptr - packet->nx_packet_prepend_ptr;

            // NetXDuo takes ownership of the packet on success
            UINT status = nx_tcp_socket_send(mTCP, packet, NX_NO_WAIT);
            if (status != NX_SUCCESS)
            {
                // Don't leak the packet
                nx_packet_release(packet);
                err = chip::System::MapErrorNetXDuo(status);
                break;
            }

            // Mark the connection as being active.
            MarkActive();

            if (OnDataSent != nullptr)
            {
                OnDataSent(this, static_cast<uint16_t>(len));
            }
        }
    }
    else
        err = CHIP_ERROR_CONNECTION_ABORTED;

    return err;
}

void TCPEndPointImplNetXDuo::HandleConnectCompleteImpl() {}

void TCPEndPointImplNetXDuo::DoCloseImpl(CHIP_ERROR err, State oldState)
{
    // If the socket hasn't been closed yet...
    if (mTCP != NULL)
    {
        nx_tcp_socket_disconnect(mTCP, 0);

        /*
         * Make sure we free up any resources which may have been allocated for the socket.
         * We don't check the return status since there's nothing we can do about it.
         */

        nx_tcp_server_socket_unaccept(mTCP);

        // If the endpoint was a listening endpoint
        if (oldState == State::kListening)
        {
            nx_tcp_server_socket_unlisten(mTCP->nx_tcp_socket_ip_ptr, mTCP->nx_tcp_socket_port);
        }
        nx_tcp_client_socket_unbind(mTCP);
        nx_tcp_socket_delete(mTCP);

        // Discard the reference to the socket to ensure there is no further interaction with it
        // after this point.
        free(mTCP);
        mTCP                 = NULL;
        mBoundPort           = 0;
        mNetXDuoEndPointType = NetXDuoEndPointType::Unknown;
    }
}

CHIP_ERROR TCPEndPointImplNetXDuo::AckReceive(size_t len)
{
    VerifyOrReturnError(IsConnected(), CHIP_ERROR_INCORRECT_STATE);

    // nothing to do for NetXDuo case
    return CHIP_NO_ERROR;
}

#if INET_CONFIG_OVERRIDE_SYSTEM_TCP_USER_TIMEOUT
void TCPEndPointImplNetXDuo::TCPUserTimeoutHandler()
{
    // Set the timer running flag to false
    mUserTimeoutTimerRunning = false;

    // Close Connection as we have timed out and there is still
    // data not sent out successfully.
    DoClose(INET_ERROR_TCP_USER_TIMEOUT, false);
}
#endif // INET_CONFIG_OVERRIDE_SYSTEM_TCP_USER_TIMEOUT

#if 0
// May not be needed. Leave ifdef'd out until the send implementation is done.
uint16_t TCPEndPointImplNetXDuo::RemainingToSend()
{
    if (mSendQueue.IsNull())
    {
        return 0;
    }
    else
    {
        // NetXDuo doesn't have an API to return the number of bytes of unacked data.
        // There is a field in the TCP socket structure but we don't want to access that
        // while the IP thread may be modifying the value. So for now we just report
        // the amount of data in the send queue.

        return static_cast<uint16_t>(mSendQueue->TotalLength());
    }
}
#endif

CHIP_ERROR TCPEndPointImplNetXDuo::CreateSocket(NX_IP * ip, NX_TCP_SOCKET * & tcp)
{
    CHIP_ERROR err = CHIP_NO_ERROR; 
    VerifyOrReturnError(ip != NULL, CHIP_ERROR_INCORRECT_STATE);
    
    NX_TCP_SOCKET * new_socket = static_cast<NX_TCP_SOCKET *>(malloc(sizeof(NX_TCP_SOCKET)));
    if (new_socket == NULL)
    {
        return CHIP_ERROR_NO_MEMORY;
    }

    UINT status;
    status = nx_tcp_socket_create(ip, new_socket, NULL,
                        NX_IP_NORMAL, NX_FRAGMENT_OKAY, NX_IP_TIME_TO_LIVE,
                        NX_TCP_WINDOW_SIZE, NULL, NULL);
    if (status != NX_SUCCESS)
    {
        free(new_socket);
        err = chip::System::MapErrorNetXDuo(status);
        return err;
    }

    tcp = new_socket;
    nx_tcp_socket_receive_notify(tcp, NetXDuoHandleDataReceived);
    return err;
}

CHIP_ERROR TCPEndPointImplNetXDuo::GetSocket(NX_IP * ip)
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    if (mTCP == NULL)
    {
        err = CreateSocket(ip, mTCP);

        if (err == CHIP_NO_ERROR)
        {
            mTCP->nx_tcp_socket_reserved_ptr = this;
            mState = State::kReady;
        }
    }

    return err;
}

void TCPEndPointImplNetXDuo::HandleDataReceived(NX_TCP_SOCKET *socket_ptr)
{
    // Only receive new data while in the Connected or SendShutdown states.
    if (mState == State::kConnected || mState == State::kSendShutdown)
    {
        // Mark the connection as being active.
        MarkActive();

        UINT status = NX_SUCCESS;
        while (status == NX_SUCCESS)
        {
            // Check for a packet to be read.
            NX_PACKET * packet;
            status = nx_tcp_socket_receive(socket_ptr, &packet, NX_NO_WAIT);
            if (status == NX_SUCCESS)
            {
                // If we received a data buffer, queue it on the receive queue.  If there's already data in
                // the queue, compact the data into the head buffer.

                System::PacketBufferHandle buf = System::PacketBufferHandle::Adopt(packet);

                if (!buf.IsNull())
                {
                    if (mRcvQueue.IsNull())
                    {
                        mRcvQueue = std::move(buf);
                    }
                    else
                    {
                        mRcvQueue->AddToEnd(std::move(buf));
                        mRcvQueue->CompactHead();
                    }
                }
            }
            else if (status != NX_NO_PACKET)
            {
                // If in the Connected state and the app has provided an OnPeerClose callback,
                // enter the ReceiveShutdown state.  Providing an OnPeerClose callback allows
                // the app to decide whether to keep the send side of the connection open after
                // the peer has closed. If no OnPeerClose is provided, we assume that the app
                // wants to close both directions and automatically enter the Closing state.
                if (mState == State::kConnected && OnPeerClose != NULL)
                    mState = State::kReceiveShutdown;
                else
                    mState = State::kClosing;

                // Call the app's OnPeerClose.
                if (OnPeerClose != NULL)
                    OnPeerClose(this);
            }
        }

        // Drive the received data into the app.
        DriveReceiving();
    }
}

void TCPEndPointImplNetXDuo::HandleIncomingConnection(TCPEndPoint * conEP)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    IPAddress peerAddr;
    uint16_t peerPort;

    if (mState == State::kListening)
    {
        // If there's no callback available, fail with an error.
        if (OnConnectionReceived == NULL)
            err = CHIP_ERROR_NO_CONNECTION_HANDLER;

        // Extract the peer's address information.
        if (err == CHIP_NO_ERROR)
            err = conEP->GetPeerInfo(&peerAddr, &peerPort);

        // If successful, call the app's callback function.
        if (err == CHIP_NO_ERROR)
            OnConnectionReceived(this, conEP, peerAddr, peerPort);

        // Otherwise clean up and call the app's error callback.
        else if (OnAcceptError != NULL)
            OnAcceptError(this, err);
    }
    else
        err = CHIP_ERROR_INCORRECT_STATE;

    // If something failed above, abort and free the connection end point.
    if (err != CHIP_NO_ERROR)
        conEP->Free();
}

void TCPEndPointImplNetXDuo::HandleError(CHIP_ERROR err)
{
    if (mState == State::kListening)
    {
        if (OnAcceptError != NULL)
            OnAcceptError(this, err);
    }
    else
        DoClose(err, false);
}

VOID TCPEndPointImplNetXDuo::NetXDuoHandleConnectComplete(NX_TCP_SOCKET *socket_ptr)
{
    /*
     * Not used until there is an environment to support nonblocking connect for NetXDuo.
     */
}

VOID TCPEndPointImplNetXDuo::NetXDuoHandleIncomingConnection(NX_TCP_SOCKET *socket_ptr, UINT port)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    NX_TCP_SOCKET * new_tcp = nullptr;
    UINT status = NX_SUCCESS;

    /*
     * Note that this callback is happening in the context of the IP thread.
     * Might need to move some of this processing to ScheduleLambda job. Need to investigate later.
     */

    if (socket_ptr == nullptr)
    {
        return;
    }

    TCPEndPointImplNetXDuo * listenEP = static_cast<TCPEndPointImplNetXDuo *>(socket_ptr->nx_tcp_socket_reserved_ptr);
    TCPEndPointImplNetXDuo * conEP    = nullptr;
    System::Layer & lSystemLayer      = listenEP->GetSystemLayer();

    // If there's no callback available, fail with an error.
    if (listenEP->OnConnectionReceived == nullptr)
    {
        err = CHIP_ERROR_NO_CONNECTION_HANDLER;
    }

    if (err == CHIP_NO_ERROR)
    {
        /*
         * Allocate a new socket structure so that we can continue listening.
         */

        err = listenEP->CreateSocket(socket_ptr->nx_tcp_socket_ip_ptr, new_tcp);
    }

    if (err == CHIP_NO_ERROR)
    {
        /*
         * Accept the incoming connection. Note that NetXDuo converts
         * the listening socket into the accepted connection.
         */

        if ((status = nx_tcp_server_socket_accept(socket_ptr, NX_NO_WAIT)) != NX_SUCCESS)
        {
            /* Set the socket back to listening */
            nx_tcp_server_socket_relisten(socket_ptr->nx_tcp_socket_ip_ptr, listenEP->mBoundPort, socket_ptr);
            err = chip::System::MapErrorNetXDuo(status);
        }
    }

    // Attempt to allocate an end point object.
    if (err == CHIP_NO_ERROR)
    {
        TCPEndPoint * connectEndPoint = nullptr;
        err                           = listenEP->GetEndPointManager().NewEndPoint(&connectEndPoint);
        conEP                         = static_cast<TCPEndPointImplNetXDuo *>(connectEndPoint);
    }

    // If all went well...
    if (err == CHIP_NO_ERROR)
    {
        /*
         * Move the accepted socket onto the new connection endpoint and put it in the
         * connected state. Attach the new socket to the listen endpoint and put it back
         * in the listening state.
         */

        conEP->mState               = State::kConnected;
        conEP->mTCP                 = socket_ptr;
        conEP->mNetXDuoEndPointType = NetXDuoEndPointType::TCP;
        conEP->Retain();

        listenEP->mTCP                      = new_tcp;
        new_tcp->nx_tcp_socket_reserved_ptr = listenEP;
        nx_tcp_server_socket_relisten(new_tcp->nx_tcp_socket_ip_ptr, listenEP->mBoundPort, new_tcp);
        new_tcp = nullptr;

        // Post a callback to the HandleConnectionReceived() function, passing it the new end point.
        listenEP->Retain();
        conEP->Retain();
        err = lSystemLayer.ScheduleLambda([listenEP, conEP] {
            listenEP->HandleIncomingConnection(conEP);
            conEP->Release();
            listenEP->Release();
        });
        if (err != CHIP_NO_ERROR)
        {
            conEP->Release(); // for the Ref in ScheduleLambda
            listenEP->Release();
            err = CHIP_ERROR_CONNECTION_ABORTED;
            conEP->Release(); // for the Retain() above
            conEP->Release(); // for the implied Retain() on construction
        }
        return;
    }
    // Otherwise, there was an error accepting the connection, so post a callback to the HandleError function.
    else
    {
        listenEP->Retain();
        err = lSystemLayer.ScheduleLambda([listenEP, err] {
            listenEP->HandleError(err);
            listenEP->Release();
        });
        if (err != CHIP_NO_ERROR)
        {
            listenEP->Release();
        }
    }

    // Make sure we don't leak the socket structure.
    if (new_tcp != nullptr)
    {
        free(new_tcp);
    }
}

VOID TCPEndPointImplNetXDuo::NetXDuoHandleDataReceived(NX_TCP_SOCKET *socket_ptr)
{
    if (socket_ptr != NULL)
    {
        TCPEndPointImplNetXDuo * ep = static_cast<TCPEndPointImplNetXDuo *>(socket_ptr->nx_tcp_socket_reserved_ptr);

        if (ep != NULL)
        {
            // Post callback to HandleDataReceived.
            ep->Retain();
            CHIP_ERROR err = ep->GetSystemLayer().ScheduleLambda([ep, socket_ptr] {
                ep->HandleDataReceived(socket_ptr);
                ep->Release();
            });
            if (err != CHIP_NO_ERROR)
            {
                ep->Release();
            }
        }
    }
}

} // namespace Inet
} // namespace chip
