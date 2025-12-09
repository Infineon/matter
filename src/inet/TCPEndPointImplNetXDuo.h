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
 *    @file
 *      This header file defines the <tt>Inet::TCPEndPoint</tt>
 *      class, where the CHIP Inet Layer encapsulates methods for
 *      interacting with TCP transport endpoints (SOCK_DGRAM sockets
 *      on Linux and BSD-derived systems) or LwIP TCP protocol
 *      control blocks, as the system is configured accordingly.
 */

/**
 * This file declares an implementation of Inet::TCPEndPoint using LwIP.
 */

#pragma once

#include <inet/EndPointStateNetXDuo.h>
#include <inet/TCPEndPoint.h>

namespace chip {
namespace Inet {

class TCPEndPointImplNetXDuo : public TCPEndPoint, public EndPointStateNetXDuo
{
public:
    TCPEndPointImplNetXDuo(EndPointManager<TCPEndPoint> & endPointManager) :
        TCPEndPoint(endPointManager), mTCP(nullptr)
    {}

    // TCPEndPoint overrides.
    CHIP_ERROR GetPeerInfo(IPAddress * retAddr, uint16_t * retPort) const override;
    CHIP_ERROR GetLocalInfo(IPAddress * retAddr, uint16_t * retPort) const override;
    CHIP_ERROR GetInterfaceId(InterfaceId * retInterface) override;
    CHIP_ERROR EnableNoDelay() override;
    CHIP_ERROR EnableKeepAlive(uint16_t interval, uint16_t timeoutCount) override;
    CHIP_ERROR DisableKeepAlive() override;
    CHIP_ERROR AckReceive(size_t len) override;
#if INET_CONFIG_OVERRIDE_SYSTEM_TCP_USER_TIMEOUT
    void TCPUserTimeoutHandler() override;
#endif // INET_CONFIG_OVERRIDE_SYSTEM_TCP_USER_TIMEOUT

private:
    // TCPEndPoint overrides.
    CHIP_ERROR BindImpl(IPAddressType addrType, const IPAddress & addr, uint16_t port, bool reuseAddr) override;
    CHIP_ERROR ListenImpl(uint16_t backlog) override;
    CHIP_ERROR ConnectImpl(const IPAddress & addr, uint16_t port, InterfaceId intfId) override;
    CHIP_ERROR SendQueuedImpl(bool queueWasEmpty) override;
    CHIP_ERROR SetUserTimeoutImpl(uint32_t userTimeoutMillis) override;
    CHIP_ERROR DriveSendingImpl() override;
    void HandleConnectCompleteImpl() override;
    void DoCloseImpl(CHIP_ERROR err, State oldState) override;

    NX_TCP_SOCKET * mTCP;
    uint16_t mBoundPort;

    CHIP_ERROR CreateSocket(NX_IP * ip, NX_TCP_SOCKET * & tcp);
    CHIP_ERROR GetSocket(NX_IP * ip);
    void HandleDataSent(uint16_t len);
    void HandleDataReceived(NX_TCP_SOCKET *socket_ptr);
    void HandleIncomingConnection(TCPEndPoint * conEP);
    void HandleError(CHIP_ERROR err);

    static VOID NetXDuoHandleConnectComplete(NX_TCP_SOCKET *socket_ptr);
    static VOID NetXDuoHandleIncomingConnection(NX_TCP_SOCKET *socket_ptr, UINT port);
    static VOID NetXDuoHandleDataReceived(NX_TCP_SOCKET *socket_ptr);
};

using TCPEndPointImpl = TCPEndPointImplNetXDuo;

} // namespace Inet
} // namespace chip
