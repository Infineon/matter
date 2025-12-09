/*
 *
 *    Copyright (c) 2021 Project CHIP Authors
 *    Copyright (c) 2018 Nest Labs, Inc.
 *    All rights reserved.
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
 *          General utility methods for the cyw955913 platform.
 */
/* this file behaves like a config.h, comes first */
#include <platform/internal/CHIPDeviceLayerInternal.h>

#include "cy_nw_helper.h"
#include "cy_network_mw_core.h"
#include <cy_wcm.h>
#include <lib/core/ErrorStr.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/Infineon/cat5/CYW955913Utils.h>

#include <cyabs_rtos.h>
#include <nx_api.h>
#include <malloc.h>
#include <platform/Infineon/cat5/CYW955913Config.h>
#include <packet_pool_utils.h>

extern "C" cy_rslt_t cy_wcm_get_whd_interface(cy_wcm_interface_t interface_type, whd_interface_t *whd_iface);

using namespace ::chip::DeviceLayer::Internal;
using chip::DeviceLayer::Internal::DeviceNetworkInfo;

/** ping delay - in milliseconds */
#ifndef PING_DELAY
#define PING_DELAY 2000
#endif

/** ping identifier - must fit on a u16_t */
#ifndef PING_ID
#define PING_ID 0xAFAF
#endif

/** ping additional data size to include in the packet */
#ifndef PING_DATA_SIZE
#define PING_DATA_SIZE 64
#endif

/** ping receive timeout - in milliseconds */
#ifndef PING_RCV_TIMEO
#define PING_RCV_TIMEO 5000
#endif

/* Ping IP Header len for IPv4 */
#define IP_HDR_LEN 20

/* Ping Response length */
#define PING_RESPONSE_LEN 64

/* For connect to AP routine */
#define CONNECT_AP_MAX_RETRIES          3
#define CONNECT_AP_TIME_BETWEEN_RETRIES 1000

namespace {
wifi_config_t wifi_conf;
wifi_mode_t WiFiMode;
bool wcm_init_done;
} // namespace

CHIP_ERROR CYW955913Utils::IsAPEnabled(bool & apEnabled)
{
    apEnabled = (WiFiMode == WIFI_MODE_AP || WiFiMode == WIFI_MODE_APSTA);
    return CHIP_NO_ERROR;
}

CHIP_ERROR CYW955913Utils::IsStationEnabled(bool & staEnabled)
{
    staEnabled = (WiFiMode == WIFI_MODE_STA || WiFiMode == WIFI_MODE_APSTA);
    return CHIP_NO_ERROR;
}

bool CYW955913Utils::IsStationProvisioned(void)
{
    wifi_config_t stationConfig;
    return (cyw955913_wifi_get_config(WIFI_IF_STA, &stationConfig) == CHIP_NO_ERROR && strlen((const char *) stationConfig.sta.ssid) != 0);
}

CHIP_ERROR CYW955913Utils::IsStationConnected(bool & connected)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    connected      = cy_wcm_is_connected_to_ap();
    return err;
}

CHIP_ERROR CYW955913Utils::StartWiFiLayer(void)
{
    CHIP_ERROR err   = CHIP_NO_ERROR;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    cy_wcm_config_t wcm_config;

    wcm_config.interface = CY_WCM_INTERFACE_TYPE_AP_STA;
    ChipLogProgress(DeviceLayer, "Starting cyw955913 WiFi layer");

    if (wcm_init_done == false)
    {
        result = cy_wcm_init(&wcm_config);
        if (result != CY_RSLT_SUCCESS)
        {
            err = CHIP_ERROR_INTERNAL;
            ChipLogError(DeviceLayer, "StartWiFiLayer() cyw955913 Wi-Fi Started Failed: %s", chip::ErrorStr(err));
            SuccessOrExit(err);
        }
        wcm_init_done = true;
#if CHIP_SYSTEM_CONFIG_USE_NETXDUO
        // Register the packet pools.
        NX_PACKET_POOL * tx_packet_pool;
        NX_PACKET_POOL * rx_packet_pool;
        whd_interface_t whd_iface;

        cy_network_get_packet_pool(CY_NETWORK_PACKET_TX, reinterpret_cast<void**>(&tx_packet_pool));
        cy_network_get_packet_pool(CY_NETWORK_PACKET_RX, reinterpret_cast<void**>(&rx_packet_pool));
        netxduo_register_packet_pools(tx_packet_pool, rx_packet_pool);
        cy_wcm_get_whd_interface(CY_WCM_INTERFACE_TYPE_STA, &whd_iface);
        cy_network_create_ip_instance(CY_NETWORK_WIFI_STA_INTERFACE, whd_iface);
#endif
    }

exit:
    return err;
}

CHIP_ERROR CYW955913Utils::EnableStationMode(void)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    ChipLogProgress(DeviceLayer, "EnableStationMode");
    /* If Station Mode is already set , update Mode to APSTA Mode */
    if (WiFiMode == WIFI_MODE_AP)
    {
        WiFiMode = WIFI_MODE_APSTA;
    }
    else
    {
        WiFiMode = WIFI_MODE_STA;
    }
    wifi_set_mode(WiFiMode);
    return err;
}

CHIP_ERROR CYW955913Utils::SetAPMode(bool enabled)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    ChipLogProgress(DeviceLayer, "SetAPMode");
    /* If AP Mode is already set , update Mode to APSTA Mode */
    if (enabled)
    {
        if (WiFiMode == WIFI_MODE_STA)
        {
            WiFiMode = WIFI_MODE_APSTA;
        }
        else
        {
            WiFiMode = WIFI_MODE_AP;
        }
    }
    else
    {
        if (WiFiMode == WIFI_MODE_APSTA)
        {
            WiFiMode = WIFI_MODE_STA;
        }
        else if (WiFiMode == WIFI_MODE_AP)
        {
            WiFiMode = WIFI_MODE_NULL;
        }
    }
    return err;
}

const char * CYW955913Utils::WiFiModeToStr(wifi_mode_t wifiMode)
{
    switch (wifiMode)
    {
    case WIFI_MODE_NULL:
        return "NULL";
    case WIFI_MODE_STA:
        return "STA";
    case WIFI_MODE_AP:
        return "AP";
    case WIFI_MODE_APSTA:
        return "STA+AP";
    default:
        return "(unknown)";
    }
}

CHIP_ERROR CYW955913Utils::GetWiFiSSID(char * buf, size_t bufSize)
{
    size_t num = 0;
    return CYW955913Config::ReadConfigValueStr(CYW955913Config::kConfigKey_WiFiSSID, buf, bufSize, num);
}

CHIP_ERROR CYW955913Utils::StoreWiFiSSID(char * buf, size_t size)
{
    return CYW955913Config::WriteConfigValueStr(CYW955913Config::kConfigKey_WiFiSSID, buf, size);
}

CHIP_ERROR CYW955913Utils::GetWiFiPassword(char * buf, size_t bufSize)
{
    size_t num = 0;
    return CYW955913Config::ReadConfigValueStr(CYW955913Config::kConfigKey_WiFiPassword, buf, bufSize, num);
}

CHIP_ERROR CYW955913Utils::StoreWiFiPassword(char * buf, size_t size)
{
    return CYW955913Config::WriteConfigValueStr(CYW955913Config::kConfigKey_WiFiPassword, buf, size);
}

CHIP_ERROR CYW955913Utils::GetWiFiSecurityCode(uint32_t & security)
{
    return CYW955913Config::ReadConfigValue(CYW955913Config::kConfigKey_WiFiSecurity, security);
}

CHIP_ERROR CYW955913Utils::StoreWiFiSecurityCode(uint32_t security)
{
    return CYW955913Config::WriteConfigValue(CYW955913Config::kConfigKey_WiFiSecurity, security);
}

CHIP_ERROR CYW955913Utils::wifi_get_mode(uint32_t & mode)
{
    return CYW955913Config::ReadConfigValue(CYW955913Config::kConfigKey_WiFiMode, mode);
}

CHIP_ERROR CYW955913Utils::wifi_set_mode(uint32_t mode)
{
    return CYW955913Config::WriteConfigValue(CYW955913Config::kConfigKey_WiFiMode, mode);
}

CHIP_ERROR CYW955913Utils::cyw955913_wifi_set_config(wifi_interface_t interface, wifi_config_t * conf)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    if (interface == WIFI_IF_STA)
    {
        /* Store Wi-Fi Configurations in Storage */
        err = StoreWiFiSSID((char *) conf->sta.ssid, strlen((char *) conf->sta.ssid));
        SuccessOrExit(err);

        err = StoreWiFiPassword((char *) conf->sta.password, strlen((char *) conf->sta.password));
        SuccessOrExit(err);

        err = StoreWiFiSecurityCode(conf->sta.security);
        SuccessOrExit(err);
        populate_wifi_config_t(&wifi_conf, interface, &conf->sta.ssid, &conf->sta.password, conf->sta.security);
    }
    else
    {
        populate_wifi_config_t(&wifi_conf, interface, &conf->ap.ssid, &conf->ap.password, conf->ap.security);
        wifi_conf.ap.channel                = conf->ap.channel;
        wifi_conf.ap.ip_settings.ip_address = conf->ap.ip_settings.ip_address;
        wifi_conf.ap.ip_settings.netmask    = conf->ap.ip_settings.netmask;
        wifi_conf.ap.ip_settings.gateway    = conf->ap.ip_settings.gateway;
    }

exit:
    return err;
}

CHIP_ERROR CYW955913Utils::cyw955913_wifi_get_config(wifi_interface_t interface, wifi_config_t * conf)
{
    uint32 code    = 0;
    CHIP_ERROR err = CHIP_NO_ERROR;
    if (interface == WIFI_IF_STA)
    {
        if (CYW955913Config::ConfigValueExists(CYW955913Config::kConfigKey_WiFiSSID) &&
            CYW955913Config::ConfigValueExists(CYW955913Config::kConfigKey_WiFiPassword) &&
            CYW955913Config::ConfigValueExists(CYW955913Config::kConfigKey_WiFiSecurity))
        {
            /* Retrieve Wi-Fi Configurations from Storage */
            err = GetWiFiSSID((char *) conf->sta.ssid, sizeof(conf->sta.ssid));
            SuccessOrExit(err);

            err = GetWiFiPassword((char *) conf->sta.password, sizeof(conf->sta.password));
            SuccessOrExit(err);

            err = GetWiFiSecurityCode(code);
            SuccessOrExit(err);
            conf->sta.security = static_cast<cy_wcm_security_t>(code);
        }
        else
        {
            populate_wifi_config_t(conf, interface, &wifi_conf.sta.ssid, &wifi_conf.sta.password, wifi_conf.sta.security);
        }
    }
    else
    {
        populate_wifi_config_t(conf, interface, &wifi_conf.ap.ssid, &wifi_conf.ap.password, wifi_conf.ap.security);
        conf->ap.channel                = wifi_conf.ap.channel;
        conf->ap.ip_settings.ip_address = wifi_conf.ap.ip_settings.ip_address;
        conf->ap.ip_settings.netmask    = wifi_conf.ap.ip_settings.netmask;
        conf->ap.ip_settings.gateway    = wifi_conf.ap.ip_settings.gateway;
    }

exit:
    return err;
}

CHIP_ERROR CYW955913Utils::GetWiFiStationProvision(Internal::DeviceNetworkInfo & netInfo, bool includeCredentials)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    wifi_config_t stationConfig;

    err = cyw955913_wifi_get_config(WIFI_IF_STA, &stationConfig);
    SuccessOrExit(err);

    ChipLogProgress(DeviceLayer, "GetWiFiStationProvision");
    VerifyOrExit(strlen((const char *) stationConfig.sta.ssid) != 0, err = CHIP_ERROR_INCORRECT_STATE);

    netInfo.NetworkId              = kWiFiStationNetworkId;
    netInfo.FieldPresent.NetworkId = true;
    memcpy(netInfo.WiFiSSID, stationConfig.sta.ssid,
           std::min(strlen(reinterpret_cast<char *>(stationConfig.sta.ssid)) + 1, sizeof(netInfo.WiFiSSID)));

    // Enforce that netInfo wifiSSID is null terminated
    netInfo.WiFiSSID[kMaxWiFiSSIDLength] = '\0';

    if (includeCredentials)
    {
        static_assert(sizeof(netInfo.WiFiKey) < 255, "Our min might not fit in netInfo.WiFiKeyLen");
        netInfo.WiFiKeyLen = static_cast<uint8_t>(std::min(strlen((char *) stationConfig.sta.password), sizeof(netInfo.WiFiKey)));
        memcpy(netInfo.WiFiKey, stationConfig.sta.password, netInfo.WiFiKeyLen);
    }

exit:
    return err;
}

CHIP_ERROR CYW955913Utils::SetWiFiStationProvision(const Internal::DeviceNetworkInfo & netInfo)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    wifi_config_t wifiConfig;
    ChipLogProgress(DeviceLayer, "SetWiFiStationProvision");
    char wifiSSID[kMaxWiFiSSIDLength + 1];
    size_t netInfoSSIDLen = strlen(netInfo.WiFiSSID);

    // Ensure that cyw955913 station mode is enabled.  This is required before cyw955913_wifi_set_config
    // can be called.
    err = CYW955913Utils::EnableStationMode();
    SuccessOrExit(err);

    // Enforce that wifiSSID is null terminated before copying it
    memcpy(wifiSSID, netInfo.WiFiSSID, std::min(netInfoSSIDLen + 1, sizeof(wifiSSID)));
    if (netInfoSSIDLen + 1 < sizeof(wifiSSID))
    {
        wifiSSID[netInfoSSIDLen] = '\0';
    }
    else
    {
        wifiSSID[kMaxWiFiSSIDLength] = '\0';
    }

    // Initialize an cyw955913 wifi_config_t structure based on the new provision information.
    populate_wifi_config_t(&wifiConfig, WIFI_IF_STA, (cy_wcm_ssid_t *) wifiSSID, (cy_wcm_passphrase_t *) netInfo.WiFiKey);

    // Configure the cyw955913 WiFi interface.
    ReturnLogErrorOnFailure(cyw955913_wifi_set_config(WIFI_IF_STA, &wifiConfig));

    ChipLogProgress(DeviceLayer, "WiFi station provision set (SSID: %s)", netInfo.WiFiSSID);

exit:
    return err;
}

CHIP_ERROR CYW955913Utils::ClearWiFiStationProvision(void)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    wifi_config_t stationConfig;
    ChipLogProgress(DeviceLayer, "ClearWiFiStationProvision");
    // Clear the cyw955913 WiFi station configuration.
    memset(&stationConfig.sta, 0, sizeof(stationConfig.sta));
    ReturnLogErrorOnFailure(cyw955913_wifi_set_config(WIFI_IF_STA, &stationConfig));
    return err;
}

CHIP_ERROR CYW955913Utils::cyw955913_wifi_disconnect(void)
{
    CHIP_ERROR err   = CHIP_NO_ERROR;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    ChipLogProgress(DeviceLayer, "cyw955913_wifi_disconnect");
    result = cy_wcm_disconnect_ap();
    if (result != CY_RSLT_SUCCESS)
    {
        ChipLogError(DeviceLayer, "cyw955913_wifi_disconnect() failed result %ld", result);
        err = CHIP_ERROR_INTERNAL;
    }
    return err;
}

CHIP_ERROR CYW955913Utils::cyw955913_wifi_connect(void)
{
    CHIP_ERROR err   = CHIP_NO_ERROR;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    wifi_config_t stationConfig;
    cy_wcm_connect_params_t connect_param;
    cy_wcm_ip_address_t ip_addr;
    uint8_t cy_wcm_connect_ap_retry_count = 0;

    cyw955913_wifi_get_config(WIFI_IF_STA, &stationConfig);
    memset(&connect_param, 0, sizeof(cy_wcm_connect_params_t));
    memset(&ip_addr, 0, sizeof(cy_wcm_ip_address_t));
    memcpy(&connect_param.ap_credentials.SSID, &stationConfig.sta.ssid, strlen((char *) stationConfig.sta.ssid));
    memcpy(&connect_param.ap_credentials.password, &stationConfig.sta.password, strlen((char *) stationConfig.sta.password));
    connect_param.ap_credentials.security = stationConfig.sta.security;

    ChipLogProgress(DeviceLayer, "Connecting to AP : [%s] \r\n", connect_param.ap_credentials.SSID);

    while (true)
    {
        result = cy_wcm_connect_ap(&connect_param, &ip_addr);
        if (result != CY_RSLT_SUCCESS)
        {
            err = CHIP_ERROR_INTERNAL;
            cy_wcm_connect_ap_retry_count++;

            if (cy_wcm_connect_ap_retry_count >= CONNECT_AP_MAX_RETRIES)
            {
                ChipLogError(DeviceLayer, "Exceeded max WiFi connection attempts\n");
                break;
            }
            ChipLogError(DeviceLayer, "cy_wcm_connect_ap() failed result 0x%X. Retrying...", (unsigned int)result);

            // In case the AP is currently unavailable
            if (result == CY_RSLT_WCM_SECURITY_NOT_FOUND)
            {
                err = CHIP_ERROR(CY_RSLT_WCM_SECURITY_NOT_FOUND);
                break;
            }
        }
        else
        {
            err = CHIP_NO_ERROR;
            break;
        }
        cy_rtos_delay_milliseconds(CONNECT_AP_TIME_BETWEEN_RETRIES);
    }

    return err;
}

#define INITIALISER_IPV4_ADDRESS1(addr_var, addr_val) addr_var = { CY_WCM_IP_VER_V4, { .v4 = (uint32_t) (addr_val) } }
#define MAKE_IPV4_ADDRESS1(a, b, c, d) ((((uint32_t) d) << 24) | (((uint32_t) c) << 16) | (((uint32_t) b) << 8) | ((uint32_t) a))
static const cy_wcm_ip_setting_t ap_mode_ip_settings2 = {
    INITIALISER_IPV4_ADDRESS1(.ip_address, MAKE_IPV4_ADDRESS1(192, 168, 0, 2)),
    INITIALISER_IPV4_ADDRESS1(.gateway, MAKE_IPV4_ADDRESS1(192, 168, 0, 2)),
    INITIALISER_IPV4_ADDRESS1(.netmask, MAKE_IPV4_ADDRESS1(255, 255, 255, 0)),
};

CHIP_ERROR CYW955913Utils::cyw955913_start_ap(void)
{
    CHIP_ERROR err   = CHIP_NO_ERROR;
    cy_rslt_t result = CY_RSLT_SUCCESS;

    wifi_config_t stationConfig;
    memset(&stationConfig, 0, sizeof(stationConfig));
    cyw955913_wifi_get_config(WIFI_IF_AP, &stationConfig);

    cy_wcm_ap_config_t ap_conf;
    memset(&ap_conf, 0, sizeof(cy_wcm_ap_config_t));
    memcpy(ap_conf.ap_credentials.SSID, &stationConfig.ap.ssid, strlen((const char *) stationConfig.ap.ssid));
    memcpy(ap_conf.ap_credentials.password, &stationConfig.ap.password, strlen((const char *) stationConfig.ap.password));
    memcpy(&ap_conf.ip_settings, &stationConfig.ap.ip_settings, sizeof(stationConfig.ap.ip_settings));
    ap_conf.ap_credentials.security = stationConfig.ap.security;
    ap_conf.channel                 = stationConfig.ap.channel;
    ChipLogProgress(DeviceLayer, "cyw955913_start_ap %s \r\n", ap_conf.ap_credentials.SSID);

    /* Start AP */
    result = cy_wcm_start_ap(&ap_conf);
    if (result != CY_RSLT_SUCCESS)
    {
        ChipLogError(DeviceLayer, "cy_wcm_start_ap() failed result %ld", result);
        err = CHIP_ERROR_INTERNAL;
    }
    /* Link Local IPV6 AP address for AP */
    cy_wcm_ip_address_t ipv6_addr;
    result = cy_wcm_get_ipv6_addr(CY_WCM_INTERFACE_TYPE_AP, CY_WCM_IPV6_LINK_LOCAL, &ipv6_addr);
    if (result != CY_RSLT_SUCCESS)
    {
        ChipLogError(DeviceLayer, "cy_wcm_get_ipv6_addr() failed result %ld", result);
        err = CHIP_ERROR_INTERNAL;
    }
    return err;
}

CHIP_ERROR CYW955913Utils::cyw955913_stop_ap(void)
{
    CHIP_ERROR err   = CHIP_NO_ERROR;
    cy_rslt_t result = CY_RSLT_SUCCESS;
    /* Stop AP */
    result = cy_wcm_stop_ap();
    if (result != CY_RSLT_SUCCESS)
    {
        ChipLogError(DeviceLayer, "cy_wcm_stop_ap failed result %ld", result);
        err = CHIP_ERROR_INTERNAL;
    }
    return err;
}

void CYW955913Utils::populate_wifi_config_t(wifi_config_t * wifi_config, wifi_interface_t interface, const cy_wcm_ssid_t * ssid,
                                     const cy_wcm_passphrase_t * password, cy_wcm_security_t security)
{
    CY_ASSERT(wifi_config != NULL);

    // Use interface param to determine which config to fill out
    if (interface == WIFI_IF_STA || interface == WIFI_IF_STA_AP)
    {
        memset(&wifi_config->sta, 0, sizeof(wifi_config_sta_t));
        memcpy(wifi_config->sta.ssid, ssid, std::min(strlen((char *) ssid) + 1, sizeof(cy_wcm_ssid_t)));
        memcpy(wifi_config->sta.password, password, std::min(strlen((char *) password) + 1, sizeof(cy_wcm_ssid_t)));
        wifi_config->sta.security = security;
    }

    if (interface == WIFI_IF_AP || interface == WIFI_IF_STA_AP)
    {
        memset(&wifi_config->ap, 0, sizeof(wifi_config_ap_t));
        memcpy(wifi_config->ap.ssid, ssid, std::min(strlen((char *) ssid) + 1, sizeof(cy_wcm_ssid_t)));
        memcpy(wifi_config->ap.password, password, std::min(strlen((char *) password) + 1, sizeof(cy_wcm_ssid_t)));
        wifi_config->ap.security = security;
    }
}

/* Ping implementation
 *
 */

static void print_ip4(uint32_t ip)
{
    unsigned int bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("Addr = %d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);
}

static void ping_socket(NX_IP * net_interface)
{
    UINT status;
    uint32_t addr;
    char ping_str[] = "ICMP Socket Ping.\n";
    NX_PACKET *resp_packet;
    ULONG wait_time = 1000; // one second timeout
    cy_time_t send_time;
    cy_time_t recv_time;
    int frame_size = strlen(ping_str);

    status = nx_ip_gateway_address_get(net_interface, &addr);
    NX_ASSERT(status == NX_SUCCESS);
    cy_rtos_delay_milliseconds(100);
    printf("Sending ICMP echo packet to IP.");
    cy_rtos_get_time(&send_time);
    status = nx_icmp_ping(net_interface, addr, ping_str, frame_size, &resp_packet, wait_time);
    cy_rtos_get_time(&recv_time);
    NX_ASSERT(status == NX_SUCCESS);
    print_ip4(addr);
    printf(" bytes=%d time=%ldms", strlen(ping_str), (recv_time - send_time));
    nx_packet_release(resp_packet);
    return;
}

CHIP_ERROR CYW955913Utils::ping_init(void)
{
    ULONG temp;
    CHIP_ERROR err = CHIP_NO_ERROR;
    NX_IP * net_interface = (NX_IP *)cy_network_get_nw_interface(CY_NETWORK_WIFI_STA_INTERFACE, 0);
    UINT status = nx_ip_interface_status_check(net_interface, 0, NX_IP_ADDRESS_RESOLVED, &temp, NX_NO_WAIT);

    if (status == NX_SUCCESS)
    {
        ping_socket(net_interface);
    }
    else
    {
        ChipLogError(DeviceLayer, "ping_thread failed: Invalid IP address for Ping");
        err = CHIP_ERROR_INTERNAL;
    }
    return err;
}

static int xtlv_hdr_size(uint16_t opts, const uint8_t ** data)
{
    int len = (int) OFFSETOF(xtlv_t, data); /* nominal */
    if (opts & XTLV_OPTION_LENU8)
    {
        --len;
    }
    if (opts & XTLV_OPTION_IDU8)
    {
        --len;
    }
    return len;
}

static int xtlv_size_for_data(int dlen, uint16_t opts, const uint8_t ** data)
{
    int hsz;
    hsz = xtlv_hdr_size(opts, data);
    return ((opts & XTLV_OPTION_ALIGN32) ? CYW955913_ALIGN_SIZE(dlen + hsz, 4) : (dlen + hsz));
}

static int xtlv_len(const xtlv_t * elt, uint16_t opts)
{
    const uint8_t * lenp;
    int len;

    lenp = (const uint8_t *) &elt->len; /* nominal */
    if (opts & XTLV_OPTION_IDU8)
    {
        --lenp;
    }
    if (opts & XTLV_OPTION_LENU8)
    {
        len = *lenp;
    }
    else
    {
        len = _LTOH16_UA(lenp);
    }
    return len;
}

static int xtlv_id(const xtlv_t * elt, uint16_t opts)
{
    int id = 0;
    if (opts & XTLV_OPTION_IDU8)
    {
        id = *(const uint8_t *) elt;
    }
    else
    {
        id = _LTOH16_UA((const uint8_t *) elt);
    }
    return id;
}

static void xtlv_unpack_xtlv(const xtlv_t * xtlv, uint16_t * type, uint16_t * len, const uint8_t ** data, uint16_t opts)
{
    if (type)
    {
        *type = (uint16_t) xtlv_id(xtlv, opts);
    }
    if (len)
    {
        *len = (uint16_t) xtlv_len(xtlv, opts);
    }
    if (data)
    {
        *data = (const uint8_t *) xtlv + xtlv_hdr_size(opts, data);
    }
}

void CYW955913Utils::unpack_xtlv_buf(const uint8_t * tlv_buf, uint16_t buflen, wl_cnt_ver_30_t * cnt, wl_cnt_ge40mcst_v1_t * cnt_ge40)
{
    uint16_t len;
    uint16_t type;
    int size;
    const xtlv_t * ptlv;
    int sbuflen = buflen;
    const uint8_t * data;
    int hdr_size;
    hdr_size = xtlv_hdr_size(XTLV_OPTION_ALIGN32, &data);
    while (sbuflen >= hdr_size)
    {
        ptlv = (const xtlv_t *) tlv_buf;

        xtlv_unpack_xtlv(ptlv, &type, &len, &data, XTLV_OPTION_ALIGN32);
        size = xtlv_size_for_data(len, XTLV_OPTION_ALIGN32, &data);

        sbuflen -= size;
        if (sbuflen < 0) /* check for buffer overrun */
        {
            break;
        }
        if (type == 0x100)
        {
            memcpy(cnt, (wl_cnt_ver_30_t *) data, sizeof(wl_cnt_ver_30_t));
        }
        if (type == 0x400)
        {
            memcpy(cnt_ge40, (wl_cnt_ge40mcst_v1_t *) data, sizeof(wl_cnt_ge40mcst_v1_t));
        }
        tlv_buf += size;
    }
}

/* Get the Heap total size for cyw955913 Linker file */
uint32_t get_heap_total()
{
    extern uint8_t __HeapBase;  /* Symbol exported by the linker. */
    extern uint8_t __HeapLimit; /* Symbol exported by the linker. */

    uint8_t * heap_base  = (uint8_t *) &__HeapBase;
    uint8_t * heap_limit = (uint8_t *) &__HeapLimit;
    return (uint32_t) (heap_limit - heap_base);
}

/* Populate Heap info based on heap total size and Current Heap usage */
void CYW955913Utils::heap_usage(heap_info_t * heap)
{
    struct mallinfo mall_info = mallinfo();

    heap->HeapMax  = mall_info.arena;
    heap->HeapUsed = mall_info.uordblks;
    heap->HeapFree = get_heap_total() - mall_info.uordblks;
}
