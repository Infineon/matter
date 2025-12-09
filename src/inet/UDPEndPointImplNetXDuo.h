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
 * This file declares an implementation of Inet::UDPEndPoint using LwIP.
 */

#pragma once

#include <inet/EndPointStateNetXDuo.h>
#include <inet/UDPEndPoint.h>

namespace chip {
namespace Inet {

class UDPEndPointImplNetXDuo : public UDPEndPoint, public EndPointStateNetXDuo
{
public:
    UDPEndPointImplNetXDuo(EndPointManager<UDPEndPoint> & endPointManager) : UDPEndPoint(endPointManager), mUDP(nullptr) {}

    // UDPEndPoint overrides.
    CHIP_ERROR SetMulticastLoopback(IPVersion aIPVersion, bool aLoopback) override;
    InterfaceId GetBoundInterface() const override;
    uint16_t GetBoundPort() const override;
    void Free() override;

private:
    // UDPEndPoint overrides.
#if INET_CONFIG_ENABLE_IPV4
    CHIP_ERROR IPv4JoinLeaveMulticastGroupImpl(InterfaceId aInterfaceId, const IPAddress & aAddress, bool join) override;
#endif // INET_CONFIG_ENABLE_IPV4
    CHIP_ERROR IPv6JoinLeaveMulticastGroupImpl(InterfaceId aInterfaceId, const IPAddress & aAddress, bool join) override;
    CHIP_ERROR BindImpl(IPAddressType addressType, const IPAddress & address, uint16_t port, InterfaceId interfaceId) override;
    CHIP_ERROR BindInterfaceImpl(IPAddressType addressType, InterfaceId interfaceId) override;
    CHIP_ERROR ListenImpl() override;
    CHIP_ERROR SendMsgImpl(const IPPacketInfo * pktInfo, chip::System::PacketBufferHandle && msg) override;
    void CloseImpl() override;

    void HandleDataReceived(NX_UDP_SOCKET *socket_ptr);

    CHIP_ERROR GetSocket(NX_IP * ip);
    static VOID NetXDuoHandleDataReceived(NX_UDP_SOCKET *socket_ptr);

    NX_UDP_SOCKET * mUDP;
    InterfaceId mBoundIntfId;
    uint16_t mBoundPort;
};

using UDPEndPointImpl = UDPEndPointImplNetXDuo;

} // namespace Inet
} // namespace chip
