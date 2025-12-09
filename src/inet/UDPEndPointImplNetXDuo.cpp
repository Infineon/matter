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
 * This file implements Inet::UDPEndPoint using NetXDuo.
 */

#include <inet/UDPEndPointImplNetXDuo.h>

#include <nx_api.h>
extern   "C" {
#include <nx_ipv6.h>
}

extern   "C" {
#define DEBUG_PRINTS        0

#if CYW955913EVK_01
void CYW955913Log(const char * aFormat, ...);
#define INF_LOG(...) CYW955913Log(__VA_ARGS__)
#else
void P6Log(const char * aFormat, ...);
#define INF_LOG(...) P6Log(__VA_ARGS__)
#endif
}

#ifndef NX_DEFAULT_UDP_QUEUE_SIZE
#define NX_DEFAULT_UDP_QUEUE_SIZE   (5)
#endif

namespace chip {
namespace Inet {

CHIP_ERROR UDPEndPointImplNetXDuo::BindImpl(IPAddressType addressType, const IPAddress & address, uint16_t port,
                                            InterfaceId interfaceId)
{
    NX_INTERFACE * nx_interface;
    NX_IP * ip;

    // Get the IP instance for the interface id.
    CHIP_ERROR res = interfaceId.GetNetXDuoInterfaceIP(ip, nx_interface);

    // Get a UDP socket.
    if (res == CHIP_NO_ERROR)
    {
        res = GetSocket(ip);
    }

    // Sockets are associated with an IP instance that has one or more interfaces. There
    // isn't a method for binding a UDP socket to a particular interface for an IP instance.
    if (res == CHIP_NO_ERROR)
    {
        UINT status;
        status = nx_udp_socket_bind(mUDP, port, NX_NO_WAIT);
        if (status != NX_SUCCESS)
        {
            res = chip::System::MapErrorNetXDuo(status); 
        }
    }

    if (res == CHIP_NO_ERROR)
    {
        // Store the UDP port. Query the socket in case a port of 0 was specified.
        UINT udp_port;
        nx_udp_socket_port_get(mUDP, &udp_port);
        mBoundPort   = static_cast<uint16_t>(udp_port);
        mBoundIntfId = interfaceId;
    }

    return res;
}

CHIP_ERROR UDPEndPointImplNetXDuo::BindInterfaceImpl(IPAddressType addrType, InterfaceId intfId)
{
    NX_INTERFACE * nx_interface;
    NX_IP * ip;

    // Get the IP instance for the interface id.
    CHIP_ERROR res = intfId.GetNetXDuoInterfaceIP(ip, nx_interface);

    // Get a UDP socket.
    if (res == CHIP_NO_ERROR)
    {
        res = GetSocket(ip);
    }
    
    // Sockets are associated with an IP instance that has one or more interfaces. There
    // isn't a method for binding a UDP socket to a particular interface for an IP instance.
    // So as long as the socket has been created for this IP instance, we're done.

    if (res == CHIP_NO_ERROR)
    {
        // Store the interface.
        mBoundIntfId = intfId;
    }

    return res;
}

InterfaceId UDPEndPointImplNetXDuo::GetBoundInterface() const
{
    return mBoundIntfId;
}

uint16_t UDPEndPointImplNetXDuo::GetBoundPort() const
{
    return mBoundPort;
}

CHIP_ERROR UDPEndPointImplNetXDuo::ListenImpl()
{
    nx_udp_socket_receive_notify(mUDP, NetXDuoHandleDataReceived);
    return CHIP_NO_ERROR;
}

CHIP_ERROR UDPEndPointImplNetXDuo::SendMsgImpl(const IPPacketInfo * pktInfo, System::PacketBufferHandle && msg)
{
    CHIP_ERROR res = CHIP_NO_ERROR;

    // Ensure packet buffer is not null
    VerifyOrReturnError(!msg.IsNull(), CHIP_ERROR_INVALID_ARGUMENT);

    // For now the entire message must fit within a single buffer.
    VerifyOrReturnError(!msg->HasChainedBuffer(), CHIP_ERROR_MESSAGE_TOO_LONG);

    if (mUDP == NULL)
    {
        InterfaceId intf = pktInfo->Interface;
        if (!intf.IsPresent())
        {
            intf = mBoundIntfId;
        }

        NX_INTERFACE * nx_interface;
        NX_IP * ip;

        // Get the IP instance for the interface.
        res = intf.GetNetXDuoInterfaceIP(ip, nx_interface);

        // Get a UDP socket.
        if (res == CHIP_NO_ERROR)
        {
            res = GetSocket(ip);
        }
        if (res != CHIP_NO_ERROR)
        {
#if DEBUG_PRINTS
            INF_LOG("**********SendMsgImpl: NO SOCKET");
#endif
            return res;
        }
    }

    if (!msg.HasSoleOwnership())
    {
        // when retaining a buffer, the caller expects the msg to be unmodified.
        // NetXDuo stack will prepend the packet headers as the packet traverses
        // the UDP/IP layers, which modifies the packet. We need to clone
        // msg into a fresh object in this case, and queues that for transmission, leaving
        // the original msg available after return.
        msg = msg.CloneData();
        VerifyOrReturnError(!msg.IsNull(), CHIP_ERROR_NO_MEMORY);
    }

    // Send the message to the specified address/port.
    const IPAddress & destAddr = pktInfo->DestAddress;
    const uint16_t & destPort  = pktInfo->DestPort;

    NXD_ADDRESS nxdDestAddr = destAddr.ToNetXDuoAddr();
    NX_PACKET * packet = reinterpret_cast<NX_PACKET *>(msg.PopHeadBuffer());

#if DEBUG_PRINTS
    if (1)
    {
        char addr_str[40];
        INF_LOG("=======Sending UDP packet (%p) to : %s : port %d", packet->nx_packet_prepend_ptr, pktInfo->DestAddress.ToString(addr_str, sizeof(addr_str)), destPort);
    }
#endif

    uintptr_t offset = reinterpret_cast<uintptr_t>(packet->nx_packet_prepend_ptr) & 0x3;
    if (offset != 0)
    {
        if (packet->nx_packet_append_ptr + offset > packet->nx_packet_data_end)
        {
            printf("****Insufficient space to align packet data!!!\n");
            // Don't leak the packet
            nx_packet_release(packet);
            return CHIP_ERROR_INCORRECT_STATE;

        }
        memmove(packet->nx_packet_prepend_ptr + offset, packet->nx_packet_prepend_ptr, packet->nx_packet_length);
        packet->nx_packet_prepend_ptr += offset;
        packet->nx_packet_append_ptr  += offset;
    }

    UINT status = nxd_udp_socket_send(mUDP, packet, &nxdDestAddr, static_cast<UINT>(destPort));
    if (status != NX_SUCCESS)
    {
#if DEBUG_PRINTS
        INF_LOG("=======Error returned from nxd_udp_socket_send: 0x%02x", status);
#endif
        // Don't leak the packet
        nx_packet_release(packet);
        res = CHIP_ERROR_INCORRECT_STATE;
    }

    return res;
}

void UDPEndPointImplNetXDuo::CloseImpl()
{
    if (mUDP == nullptr)
    {
        return;
    }

    // Unbind and delete the socket
    nx_udp_socket_unbind(mUDP);
    nx_udp_socket_delete(mUDP);

    free(mUDP);
    mUDP                 = nullptr;
    mBoundPort           = 0;
    mNetXDuoEndPointType = NetXDuoEndPointType::Unknown;
}

void UDPEndPointImplNetXDuo::Free()
{
    Close();
    Release();
}

void UDPEndPointImplNetXDuo::HandleDataReceived(NX_UDP_SOCKET *socket_ptr)
{

    CHIP_ERROR res = CHIP_NO_ERROR;
#if DEBUG_PRINTS
    INF_LOG("******Data received on UDP socket");
#endif
    if (mState != State::kListening || OnMessageReceived == nullptr || mUDP == nullptr)
    {
#if DEBUG_PRINTS
        INF_LOG("---------Bailing on UDP receive (%d,%p,%p)", mState != State::kListening, OnMessageReceived, mUDP);
#endif
        return;
    }

    IPPacketInfo lPacketInfo;
    UINT status = NX_SUCCESS;

    lPacketInfo.Clear();
    lPacketInfo.DestPort  = mBoundPort;
    lPacketInfo.Interface = mBoundIntfId;

    while (status == NX_SUCCESS)
    {
        // Check for a packet to be read.
        NX_PACKET * packet;
        status = nx_udp_socket_receive(mUDP, &packet, NX_NO_WAIT);
        if (status == NX_SUCCESS)
        {
#if DEBUG_PRINTS
            if (1)
            {
                ptrdiff_t len = packet->nx_packet_append_ptr - packet->nx_packet_prepend_ptr;

                INF_LOG("------Data length in received packet is %d (%ld)", len, packet->nx_packet_length);
            }
#endif
            // Find out where this packet came from

            NXD_ADDRESS ipAddr;
            UINT port;
            nxd_udp_source_extract(packet, &ipAddr, &port);
            lPacketInfo.SrcAddress = IPAddress(ipAddr);
            lPacketInfo.SrcPort    = static_cast<uint16_t>(port);
#if DEBUG_PRINTS
            {
                char addr_str[40];
                INF_LOG("------Src Address : %s : port %d", lPacketInfo.SrcAddress.ToString(addr_str, sizeof(addr_str)), port);
            }
#endif

#if INET_CONFIG_ENABLE_IPV4 && !NX_DISABLE_IPV4
            if (packet->nx_packet_ip_version == NX_IP_VERSION_V4)
            {
                lPacketInfo.DestAddress = IPAddress(htonl(packet->nx_packet_address.nx_packet_interface_ptr->nx_interface_ip_address));
            }
#endif

#ifndef NX_DISABLE_IPV6
            if (packet->nx_packet_ip_version == NX_IP_VERSION_V6)
            {
                ULONG v6[4];
                COPY_IPV6_ADDRESS(packet->nx_packet_address.nx_packet_ipv6_address_ptr->nxd_ipv6_address, v6);
                NX_IPV6_ADDRESS_CHANGE_ENDIAN(v6);
                lPacketInfo.DestAddress = IPAddress(v6);
#if DEBUG_PRINTS
                {
                    char addr_str[40];
                    INF_LOG("------Dst Address : %s : port %d", lPacketInfo.DestAddress.ToString(addr_str, sizeof(addr_str)), lPacketInfo.DestPort);
                }
#endif
            }
#endif
            System::PacketBufferHandle lBuffer = System::PacketBufferHandle::Adopt(packet);

            OnMessageReceived(this, std::move(lBuffer), &lPacketInfo);
        }
        else if (status != NX_NO_PACKET)
        {
            res = chip::System::MapErrorNetXDuo(status);
            if (OnReceiveError != nullptr)
            {
                OnReceiveError(this, res, nullptr);
            }
        }
    }
}

CHIP_ERROR UDPEndPointImplNetXDuo::SetMulticastLoopback(IPVersion aIPVersion, bool aLoopback)
{
    UINT status = NX_SUCCESS;

    VerifyOrReturnError(mUDP != nullptr, CHIP_ERROR_INCORRECT_STATE);

#if !defined(NX_DISABLE_LOOPBACK_INTERFACE)
    CHIP_ERROR err = CHIP_NO_ERROR;
    if (aLoopback)
    {
        status = nx_igmp_loopback_enable(mUDP->nx_udp_socket_ip_ptr);
    }
    else
    {
        status = nx_igmp_loopback_disable(mUDP->nx_udp_socket_ip_ptr);
    }
    err = chip::System::MapErrorNetXDuo(status);
    return err;
#else
    return CHIP_ERROR_UNSUPPORTED_CHIP_FEATURE;
#endif // NX_DISABLE_LOOPBACK_INTERFACE
}

#if INET_CONFIG_ENABLE_IPV4
CHIP_ERROR UDPEndPointImplNetXDuo::IPv4JoinLeaveMulticastGroupImpl(InterfaceId aInterfaceId, const IPAddress & aAddress, bool join)
{
    VerifyOrReturnError(mUDP != nullptr, CHIP_ERROR_INCORRECT_STATE);
#if INET_CONFIG_ENABLE_IPV4 && !NX_DISABLE_IPV4
    const ULONG ipV4addr = ntohl(aAddress.ToIPv4());
    CHIP_ERROR res = CHIP_NO_ERROR;
    UINT status;

    if (join)
    {
        status = nx_igmp_multicast_join(mUDP->nx_udp_socket_ip_ptr, ipV4addr);
    }
    else
    {
        status = nx_igmp_multicast_leave(mUDP->nx_udp_socket_ip_ptr, ipV4addr);
    }
    if (status != NX_SUCCESS)
    {
        res = chip::System::MapErrorNetXDuo(status);
    }
    return res;
#else  // INET_CONFIG_ENABLE_IPV4 && !NX_DISABLE_IPV4
    return CHIP_ERROR_UNSUPPORTED_CHIP_FEATURE;
#endif // INET_CONFIG_ENABLE_IPV4 && !NX_DISABLE_IPV4
}
#endif // INET_CONFIG_ENABLE_IPV4

CHIP_ERROR UDPEndPointImplNetXDuo::IPv6JoinLeaveMulticastGroupImpl(InterfaceId aInterfaceId, const IPAddress & aAddress, bool join)
{
#if defined(NX_ENABLE_IPV6_MULTICAST)
    NX_INTERFACE * nx_interface;
    NX_IP * ip;
    UINT status = NX_SUCCESS;

#if DEBUG_PRINTS
    if (1)
    {
        char addr[40];
        INF_LOG("******UDPEndPointImplNetXDuo::IPv6JoinLeaveMulticastGroupImpl...join %d, address %s", join, aAddress.ToString(addr, sizeof(addr)));
    }
#endif
    // Get the IP instance for the interface id.
    CHIP_ERROR res = aInterfaceId.GetNetXDuoInterfaceIP(ip, nx_interface);
    NXD_ADDRESS ipV6Address = aAddress.ToIPv6();

    if (res == CHIP_NO_ERROR)
    {
        if (join)
        {
            status = nxd_ipv6_multicast_interface_join(ip, &ipV6Address, nx_interface->nx_interface_index);
        }
        else
        {
            status = nxd_ipv6_multicast_interface_leave(ip, &ipV6Address, nx_interface->nx_interface_index);
        }

        if (status != NX_SUCCESS)
        {
            res = chip::System::MapErrorNetXDuo(status);
        }
    }
    else
    {
#if DEBUG_PRINTS
        INF_LOG("*****Error retrieving IP and NX_INTERFACE");
#endif
    }

    return res;
#else  // NX_ENABLE_IPV6_MULTICAST
    return CHIP_ERROR_UNSUPPORTED_CHIP_FEATURE;
#endif // NX_ENABLE_IPV6_MULTICAST
}

CHIP_ERROR UDPEndPointImplNetXDuo::GetSocket(NX_IP * ip)
{
    VerifyOrReturnError(ip != NULL, CHIP_ERROR_INCORRECT_STATE);
    CHIP_ERROR err = CHIP_NO_ERROR;

    if (mUDP == NULL)
    {
        NX_UDP_SOCKET * new_socket = static_cast<NX_UDP_SOCKET *>(malloc(sizeof(NX_UDP_SOCKET)));
        if (new_socket == NULL)
        {
            return CHIP_ERROR_NO_MEMORY;
        }

        UINT status;
        status = nx_udp_socket_create(ip, new_socket, NULL, NX_IP_NORMAL, NX_FRAGMENT_OKAY, 255, NX_DEFAULT_UDP_QUEUE_SIZE);
        if (status != NX_SUCCESS)
        {
            free(new_socket);
            err = chip::System::MapErrorNetXDuo(status);
            return err;
        }

        mUDP = new_socket;
        mUDP->nx_udp_socket_reserved_ptr = this;
    }

    return err;
}

VOID UDPEndPointImplNetXDuo::NetXDuoHandleDataReceived(NX_UDP_SOCKET *socket_ptr)
{
    if (socket_ptr != NULL)
    {
        UDPEndPointImplNetXDuo * ep = static_cast<UDPEndPointImplNetXDuo *>(socket_ptr->nx_udp_socket_reserved_ptr);

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
