/*
 *
 *    Copyright (c) 2021-2022 Project CHIP Authors
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
 *          Provides an implementation of the DiagnosticDataProvider object
 *          for CYW955913 platform.
 */

#include <platform/internal/CHIPDeviceLayerInternal.h>

#include "cyhal_system.h"
#include "cy_nw_helper.h"
#include "cy_network_mw_core.h"
#include "nx_api.h"
#include <lib/support/CHIPMemString.h>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/DiagnosticDataProvider.h>
#include <platform/Infineon/cat5/DiagnosticDataProviderImpl.h>
#include <platform/Infineon/cat5/CYW955913Utils.h>
#include "tx_thread.h"
#define DIAG_IOVAR_BUFFER_LEN 1600

extern "C" cy_rslt_t cy_wcm_get_whd_interface(cy_wcm_interface_t type, whd_interface_t *iface); 

namespace chip {
namespace DeviceLayer {

DiagnosticDataProviderImpl & DiagnosticDataProviderImpl::GetDefaultInstance()
{
    static DiagnosticDataProviderImpl sInstance;
    return sInstance;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetCurrentHeapFree(uint64_t & currentHeapFree)
{
    heap_info_t heap;
    Internal::CYW955913Utils::heap_usage(&heap);
    currentHeapFree = static_cast<uint64_t>(heap.HeapFree);
    return CHIP_NO_ERROR;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetCurrentHeapUsed(uint64_t & currentHeapUsed)
{
    // Calculate the Heap used based on Total heap - Free heap
    heap_info_t heap;
    Internal::CYW955913Utils::heap_usage(&heap);
    currentHeapUsed = static_cast<uint64_t>(heap.HeapUsed);
    return CHIP_NO_ERROR;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetCurrentHeapHighWatermark(uint64_t & currentHeapHighWatermark)
{
    heap_info_t heap;
    Internal::CYW955913Utils::heap_usage(&heap);
    currentHeapHighWatermark = static_cast<uint64_t>(heap.HeapMax);
    return CHIP_NO_ERROR;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetRebootCount(uint16_t & rebootCount)
{
    uint32_t count = 0;

    CHIP_ERROR err = ConfigurationMgr().GetRebootCount(count);

    if (err == CHIP_NO_ERROR)
    {
        VerifyOrReturnError(count <= UINT16_MAX, CHIP_ERROR_INVALID_INTEGER_VALUE);
        rebootCount = static_cast<uint16_t>(count);
    }

    return err;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetUpTime(uint64_t & upTime)
{
    System::Clock::Timestamp currentTime = System::SystemClock().GetMonotonicTimestamp();
    System::Clock::Timestamp startTime   = PlatformMgrImpl().GetStartTime();

    if (currentTime >= startTime)
    {
        upTime = std::chrono::duration_cast<System::Clock::Seconds64>(currentTime - startTime).count();
        return CHIP_NO_ERROR;
    }

    return CHIP_ERROR_INVALID_TIME;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetTotalOperationalHours(uint32_t & totalOperationalHours)
{
    uint64_t upTime = 0;

    if (GetUpTime(upTime) == CHIP_NO_ERROR)
    {
        uint32_t totalHours = 0;
        if (ConfigurationMgr().GetTotalOperationalHours(totalHours) == CHIP_NO_ERROR)
        {
            /* uptime is terms of seconds and dividing it by 3600 to calculate
             * totalOperationalHours in hours.
             */
            VerifyOrReturnError(upTime / 3600 <= UINT32_MAX, CHIP_ERROR_INVALID_INTEGER_VALUE);
            totalOperationalHours = totalHours + static_cast<uint32_t>(upTime / 3600);
            return CHIP_NO_ERROR;
        }
    }

    return CHIP_ERROR_INVALID_TIME;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetBootReason(BootReasonType & bootReason)
{
    cyhal_reset_reason_t reset_reason = cyhal_system_get_reset_reason();
    if (reset_reason == CYHAL_SYSTEM_RESET_NONE)
    {
        bootReason = BootReasonType::kPowerOnReboot;
    }
    else if (reset_reason == CYHAL_SYSTEM_RESET_WDT)
    {
        bootReason = BootReasonType::kSoftwareWatchdogReset;
    }
    else if (reset_reason == CYHAL_SYSTEM_RESET_SOFT)
    {
        bootReason = BootReasonType::kSoftwareReset;
    }
    else if (reset_reason == CYHAL_SYSTEM_RESET_HIB_WAKEUP)
    {
        bootReason = BootReasonType::kHardwareWatchdogReset;
    }
    else
    {
        bootReason = BootReasonType::kUnspecified;
    }
    return CHIP_NO_ERROR;
}

void DiagnosticDataProviderImpl::UpdateoffPremiseService(bool ipv4service, bool ipv6service)
{
    /* Enable/Disable IPv4 Off Premise Services */
    mipv4_offpremise.SetNonNull(ipv4service);

    /* Enable/Disable IPv6 Off Premise Services */
    mipv6_offpremise.SetNonNull(ipv6service);
}

CHIP_ERROR DiagnosticDataProviderImpl::GetNetworkInterfaces(NetworkInterface ** netifpp)
{
    CHIP_ERROR err                 = CHIP_NO_ERROR;
    NetworkInterface * ifp         = new NetworkInterface();
    NX_IP * net_interface   = (NX_IP *)cy_network_get_nw_interface(CY_NETWORK_WIFI_STA_INTERFACE, 0);
    u_char hw_addr[6];
    hw_addr[0] = (net_interface->nx_ip_arp_physical_address_msw >> 8) & 0xFF;
    hw_addr[1] = net_interface->nx_ip_arp_physical_address_msw & 0xFF;
    memcpy(&hw_addr[2], &net_interface->nx_ip_arp_physical_address_lsw, sizeof(uint32_t));
    if (net_interface)
    {
        /* Update Network Interface list */
        ifp->name                            = CharSpan::fromCharString(net_interface->nx_ip_name);
        ifp->isOperational                   = net_interface->nx_ip_driver_link_up;
        ifp->type                            = app::Clusters::GeneralDiagnostics::InterfaceTypeEnum::kWiFi;
        ifp->offPremiseServicesReachableIPv4 = mipv4_offpremise;
        ifp->offPremiseServicesReachableIPv6 = mipv6_offpremise;
        ifp->hardwareAddress                 = ByteSpan(hw_addr, 6U);
    }
    *netifpp = ifp;

    return err;
}

void DiagnosticDataProviderImpl::ReleaseNetworkInterfaces(NetworkInterface * netifp)
{
    while (netifp)
    {
        NetworkInterface * del = netifp;
        netifp                 = netifp->Next;
        delete del;
    }
}

/* Wi-Fi Diagnostics Cluster Support */

CHIP_ERROR DiagnosticDataProviderImpl::GetWiFiBssId(MutableByteSpan & value)
{
    VerifyOrReturnError(value.size() >= CY_WCM_MAC_ADDR_LEN, CHIP_ERROR_BUFFER_TOO_SMALL);

    cy_wcm_associated_ap_info_t ap_info;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    CHIP_ERROR err   = CHIP_NO_ERROR;
    ChipLogError(DeviceLayer, "cy_wcm_get_associated_ap_info\r\n");
    result = cy_wcm_get_associated_ap_info(&ap_info);
    if (result != CY_RSLT_SUCCESS)
    {
        ChipLogError(DeviceLayer, "cy_wcm_get_associated_ap_info failed: %d", (int) result);
        SuccessOrExit(err = CHIP_ERROR_INTERNAL);
    }
    memcpy(value.data(), ap_info.BSSID, CY_WCM_MAC_ADDR_LEN);
    value.reduce_size(CY_WCM_MAC_ADDR_LEN);

exit:
    return err;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetWiFiSecurityType(app::Clusters::WiFiNetworkDiagnostics::SecurityTypeEnum & securityType)
{
    using app::Clusters::WiFiNetworkDiagnostics::SecurityTypeEnum;

    cy_wcm_associated_ap_info_t ap_info;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    CHIP_ERROR err   = CHIP_NO_ERROR;

    result = cy_wcm_get_associated_ap_info(&ap_info);
    if (result != CY_RSLT_SUCCESS)
    {
        ChipLogError(DeviceLayer, "cy_wcm_get_associated_ap_info failed: %d", (int) result);
        SuccessOrExit(err = CHIP_ERROR_INTERNAL);
    }
    if (ap_info.security == CY_WCM_SECURITY_OPEN)
    {
        securityType = SecurityTypeEnum::kNone;
    }
    else if (ap_info.security & WPA3_SECURITY)
    {
        securityType = SecurityTypeEnum::kWpa3;
    }
    else if (ap_info.security & WPA2_SECURITY)
    {
        securityType = SecurityTypeEnum::kWpa2;
    }
    else if (ap_info.security & WPA_SECURITY)
    {
        securityType = SecurityTypeEnum::kWpa;
    }
    else if (ap_info.security & WEP_ENABLED)
    {
        securityType = SecurityTypeEnum::kWep;
    }
    else
    {
        securityType = SecurityTypeEnum::kUnspecified;
    }

exit:
    return err;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetWiFiVersion(app::Clusters::WiFiNetworkDiagnostics::WiFiVersionEnum & wiFiVersion)
{
    using app::Clusters::WiFiNetworkDiagnostics::WiFiVersionEnum;

    wl_bss_info_t bss_info;
    whd_security_t security;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    whd_interface_t ifp = NULL;

    result = cy_wcm_get_whd_interface(CY_WCM_INTERFACE_TYPE_STA, &ifp);
    if ( result != CY_RSLT_SUCCESS)
    { 
        return CHIP_ERROR_INTERNAL; 
    } 
    
    result = whd_wifi_get_ap_info(ifp, &bss_info, &security);
    if (result != CY_RSLT_SUCCESS)
    {
        ChipLogError(DeviceLayer, "whd_wifi_get_ap_info failed: %d", (int) result);
        return CHIP_ERROR_INTERNAL;
    }

    /* VHT Capable */
    if (bss_info.vht_cap)
    {
        wiFiVersion = WiFiVersionEnum::kAc;
    }
    /* HT Capable */
    else if (bss_info.n_cap)
    {
        wiFiVersion = WiFiVersionEnum::kN;
    }
    /* 11g Capable */
    else
    {
        wiFiVersion = WiFiVersionEnum::kG;
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetWiFiChannelNumber(uint16_t & channelNumber)
{
    cy_wcm_associated_ap_info_t ap_info;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    CHIP_ERROR err   = CHIP_NO_ERROR;

    result = cy_wcm_get_associated_ap_info(&ap_info);
    if (result != CY_RSLT_SUCCESS)
    {
        ChipLogError(DeviceLayer, "cy_wcm_get_associated_ap_info failed: %d", (int) result);
        SuccessOrExit(err = CHIP_ERROR_INTERNAL);
    }
    channelNumber = ap_info.channel;

exit:
    return err;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetWiFiRssi(int8_t & rssi)
{
    cy_wcm_associated_ap_info_t ap_info;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    CHIP_ERROR err   = CHIP_NO_ERROR;

    result = cy_wcm_get_associated_ap_info(&ap_info);
    if (result != CY_RSLT_SUCCESS)
    {
        ChipLogError(DeviceLayer, "cy_wcm_get_associated_ap_info failed: %d", (int) result);
        SuccessOrExit(err = CHIP_ERROR_INTERNAL);
    }
    rssi = ap_info.signal_strength;

exit:
    return err;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetWiFiBeaconRxCount(uint32_t & beaconRxCount)
{
    uint64_t count;
    ReturnErrorOnFailure(WiFiCounters(WiFiStatsCountType::kWiFiBeaconRxCount, count));

    count -= mBeaconRxCount;
    VerifyOrReturnError(count <= UINT32_MAX, CHIP_ERROR_INVALID_INTEGER_VALUE);
    beaconRxCount = static_cast<uint32_t>(count);

    return CHIP_NO_ERROR;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetWiFiBeaconLostCount(uint32_t & beaconLostCount)
{
    uint64_t count;
    ReturnErrorOnFailure(WiFiCounters(WiFiStatsCountType::kWiFiBeaconLostCount, count));

    count -= mBeaconLostCount;
    VerifyOrReturnError(count <= UINT32_MAX, CHIP_ERROR_INVALID_INTEGER_VALUE);
    beaconLostCount = static_cast<uint32_t>(count);

    return CHIP_NO_ERROR;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetWiFiCurrentMaxRate(uint64_t & currentMaxRate)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;
    cy_wcm_wlan_statistics_t stats;
    CHIP_ERROR err = CHIP_NO_ERROR;
    uint64_t count;

    result = cy_wcm_get_wlan_statistics(CY_WCM_INTERFACE_TYPE_STA, &stats);
    if (result != CY_RSLT_SUCCESS)
    {
        ChipLogError(DeviceLayer, "cy_wcm_get_wlan_statistics failed: %d", (int) result);
        SuccessOrExit(err = CHIP_ERROR_INTERNAL);
    }
    count          = stats.tx_bitrate * PHYRATE_KPBS_BYTES_PER_SEC;
    currentMaxRate = static_cast<uint32_t>(count);

exit:
    return err;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetWiFiPacketMulticastRxCount(uint32_t & packetMulticastRxCount)
{
    uint64_t count;
    ReturnErrorOnFailure(WiFiCounters(WiFiStatsCountType::kWiFiMulticastPacketRxCount, count));

    count -= mPacketMulticastRxCount;
    VerifyOrReturnError(count <= UINT32_MAX, CHIP_ERROR_INVALID_INTEGER_VALUE);
    packetMulticastRxCount = static_cast<uint32_t>(count);

    return CHIP_NO_ERROR;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetWiFiPacketMulticastTxCount(uint32_t & packetMulticastTxCount)
{
    uint64_t count;
    ReturnErrorOnFailure(WiFiCounters(WiFiStatsCountType::kWiFiMulticastPacketTxCount, count));

    count -= mPacketMulticastTxCount;
    VerifyOrReturnError(count <= UINT32_MAX, CHIP_ERROR_INVALID_INTEGER_VALUE);
    packetMulticastTxCount = static_cast<uint32_t>(count);

    return CHIP_NO_ERROR;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetWiFiPacketUnicastRxCount(uint32_t & packetUnicastRxCount)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;
    cy_wcm_wlan_statistics_t stats;
    CHIP_ERROR err = CHIP_NO_ERROR;
    uint64_t count;

    result = cy_wcm_get_wlan_statistics(CY_WCM_INTERFACE_TYPE_STA, &stats);
    if (result != CY_RSLT_SUCCESS)
    {
        ChipLogError(DeviceLayer, "cy_wcm_get_wlan_statistics failed: %d", (int) result);
        SuccessOrExit(err = CHIP_ERROR_INTERNAL);
    }
    count = stats.rx_packets;
    count -= mPacketUnicastRxCount;
    VerifyOrReturnError(count <= UINT32_MAX, CHIP_ERROR_INVALID_INTEGER_VALUE);

    packetUnicastRxCount = static_cast<uint32_t>(count);

exit:
    return err;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetWiFiPacketUnicastTxCount(uint32_t & packetUnicastTxCount)
{
    cy_rslt_t result = CY_RSLT_SUCCESS;
    cy_wcm_wlan_statistics_t stats;
    CHIP_ERROR err = CHIP_NO_ERROR;
    uint64_t count;

    result = cy_wcm_get_wlan_statistics(CY_WCM_INTERFACE_TYPE_STA, &stats);
    if (result != CY_RSLT_SUCCESS)
    {
        ChipLogError(DeviceLayer, "cy_wcm_get_wlan_statistics failed: %d", (int) result);
        SuccessOrExit(err = CHIP_ERROR_INTERNAL);
    }

    count = stats.tx_packets;
    count -= mPacketUnicastTxCount;
    VerifyOrReturnError(count <= UINT32_MAX, CHIP_ERROR_INVALID_INTEGER_VALUE);

    packetUnicastTxCount = static_cast<uint32_t>(count);

exit:
    return err;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetWiFiOverrunCount(uint64_t & overrunCount)
{
    uint64_t count;
    ReturnErrorOnFailure(WiFiCounters(WiFiStatsCountType::kWiFiOverrunCount, count));

    count -= mOverrunCount;
    VerifyOrReturnError(count <= UINT32_MAX, CHIP_ERROR_INVALID_INTEGER_VALUE);
    overrunCount = static_cast<uint32_t>(count);

    return CHIP_NO_ERROR;
}

CHIP_ERROR DiagnosticDataProviderImpl::ResetWiFiNetworkDiagnosticsCounts()
{
    uint64_t count;
    return WiFiCounters(WiFiStatsCountType::kWiFiResetCount, count);
}

void DiagnosticDataProviderImpl::ReadCounters(WiFiStatsCountType Counttype, uint64_t & count, wl_cnt_ver_30_t * cnt,
                                              wl_cnt_ge40mcst_v1_t * cnt_ge40)
{
    if ((!cnt) || (!cnt_ge40))
    {
        ChipLogError(DeviceLayer, "ReadCounters failed due to NULL Pointers passed");
        return;
    }
    /* Populate count based in the Counttype */
    switch (Counttype)
    {
    case WiFiStatsCountType::kWiFiUnicastPacketRxCount:
        count = cnt->rxfrag;
        break;
    case WiFiStatsCountType::kWiFiUnicastPacketTxCount:
        count = cnt->txfrag;
        break;
    case WiFiStatsCountType::kWiFiMulticastPacketRxCount:
        count = cnt->rxmulti;
        break;
    case WiFiStatsCountType::kWiFiMulticastPacketTxCount:
        count = cnt->txmulti;
        break;
    case WiFiStatsCountType::kWiFiOverrunCount:
        count = cnt->txnobuf + cnt->rxnobuf;
        break;
    case WiFiStatsCountType::kWiFiBeaconLostCount:
        count = cnt_ge40->missbcn_dbg;
        break;
    case WiFiStatsCountType::kWiFiBeaconRxCount:
        count = cnt_ge40->rxbeaconmbss;
        break;
    /* Update below variables during reset counts command so that next count read will be
     *  starting from these values.
     */
    case WiFiStatsCountType::kWiFiResetCount:
        mBeaconRxCount          = cnt_ge40->rxbeaconmbss;
        mBeaconLostCount        = cnt_ge40->missbcn_dbg;
        mPacketMulticastRxCount = cnt->rxmulti;
        mPacketMulticastTxCount = cnt->txmulti;
        mPacketUnicastRxCount   = cnt->rxfrag;
        mPacketUnicastTxCount   = cnt->txfrag;
        mOverrunCount           = cnt->txnobuf + cnt->rxnobuf;
        break;
    default:
        ChipLogError(DeviceLayer, "ReadCounters type not handled : %d", (int) Counttype);
        break;
    }
}
void DiagnosticDataProviderImpl::xtlv_buffer_parsing(const uint8_t * tlv_buf, uint16_t buflen, WiFiStatsCountType Counttype,
                                                     uint64_t & count)
{
    wl_cnt_ver_30_t cnt;
    wl_cnt_ge40mcst_v1_t cnt_ge40;

    /* parse the tlv buffer and populate the cnt and cnt_ge40 buffer with the counter values */
    Internal::CYW955913Utils::unpack_xtlv_buf(tlv_buf, buflen, &cnt, &cnt_ge40);

    /* Read the counter based on the Counttype passed */
    ReadCounters(Counttype, count, &cnt, &cnt_ge40);
    return;
}

CHIP_ERROR DiagnosticDataProviderImpl::WiFiCounters(WiFiStatsCountType type, uint64_t & count)
{
    cy_rslt_t result;
    uint8_t buffer[DIAG_IOVAR_BUFFER_LEN];
    wl_cnt_info_t * wl_cnt_info = NULL;
    CHIP_ERROR err              = CHIP_NO_ERROR;
    whd_interface_t ifp = NULL;

    result = cy_wcm_get_whd_interface(CY_WCM_INTERFACE_TYPE_STA, &ifp);

    if ( result != CY_RSLT_SUCCESS)
    {
       return CHIP_ERROR_INTERNAL;
    }
    
    /* Read wl counters iovar using WHD APIs */
    result = whd_wifi_get_iovar_buffer(ifp, IOVAR_STR_COUNTERS, buffer, DIAG_IOVAR_BUFFER_LEN);
    if (result != WHD_SUCCESS)
    {
        return CHIP_ERROR_INTERNAL;
    }
    wl_cnt_info =
        (wl_cnt_info_t *) buffer;

    /* Parse the buffer only for Counter Version 30 */
    if (wl_cnt_info->version == WL_CNT_VER_30)
    {
        /* 43012 board - Process xtlv buffer data to get statistics */
        uint8_t * cntdata;
        cntdata = (uint8_t *) malloc(wl_cnt_info->datalen);

        CHK_CNTBUF_DATALEN(wl_cnt_info, DIAG_IOVAR_BUFFER_LEN);
        if (cntdata == NULL)
        {
            return CHIP_ERROR_INTERNAL;
        }
        /* Allocate the memory for buffer */
        memcpy(cntdata, wl_cnt_info->data, wl_cnt_info->datalen);

        /* parse the xtlv wl counters data */
        xtlv_buffer_parsing(cntdata, wl_cnt_info->datalen, type, count);

        /* Free the memory */
        free(cntdata);
    }
    return err;
}

CHIP_ERROR DiagnosticDataProviderImpl::GetThreadMetrics(ThreadMetrics ** threadMetricsOut)
{
    /* ThreadMetrics is not supported for CYW955913EVK_01 */
    ChipLogError(DeviceLayer, "GetThreadMetrics type not supported\r\n");
    return CHIP_ERROR_UNSUPPORTED_CHIP_FEATURE;
}

void DiagnosticDataProviderImpl::ReleaseThreadMetrics(ThreadMetrics * threadMetrics)
{
    while (threadMetrics)
    {
        ThreadMetrics * del = threadMetrics;
        threadMetrics       = threadMetrics->Next;
        free(del);
    }
}

DiagnosticDataProvider & GetDiagnosticDataProviderImpl()
{
    return DiagnosticDataProviderImpl::GetDefaultInstance();
}

} // namespace DeviceLayer
} // namespace chip
