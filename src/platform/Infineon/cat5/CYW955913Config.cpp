/*
 *
 *    Copyright (c) 2021-2022 Project CHIP Authors
 *    Copyright (c) 2019-2020 Google LLC.
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
 *          Utilities for interacting with the the CYW955913 key-value store.
 */
/* this file behaves like a config.h, comes first */
#include <platform/internal/CHIPDeviceLayerInternal.h>

#include <platform/KeyValueStoreManager.h>

#include <platform/Infineon/cat5/CYW955913Config.h>

#include <lib/core/CHIPEncoding.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CHIPMemString.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/Infineon/cat5/CYW955913Utils.h>

#define KV_MAX_KEY_SIZE   64U

namespace chip {
namespace DeviceLayer {
namespace Internal {

// *** CAUTION ***: Changing the names or namespaces of these values will *break* existing devices.

// Namespaces used to store device configuration information.
const char CYW955913Config::kConfigNamespace_ChipFactory[]  = "chip-factory";
const char CYW955913Config::kConfigNamespace_ChipConfig[]   = "chip-config";
const char CYW955913Config::kConfigNamespace_ChipCounters[] = "chip-counters";

// Keys stored in the chip-factory namespace
const CYW955913Config::Key CYW955913Config::kConfigKey_SerialNum             = { kConfigNamespace_ChipFactory, "serial-num" };
const CYW955913Config::Key CYW955913Config::kConfigKey_MfrDeviceId           = { kConfigNamespace_ChipFactory, "device-id" };
const CYW955913Config::Key CYW955913Config::kConfigKey_MfrDeviceCert         = { kConfigNamespace_ChipFactory, "device-cert" };
const CYW955913Config::Key CYW955913Config::kConfigKey_MfrDeviceICACerts     = { kConfigNamespace_ChipFactory, "device-ca-certs" };
const CYW955913Config::Key CYW955913Config::kConfigKey_MfrDevicePrivateKey   = { kConfigNamespace_ChipFactory, "device-key" };
const CYW955913Config::Key CYW955913Config::kConfigKey_SoftwareVersion       = { kConfigNamespace_ChipFactory, "software-ver" };
const CYW955913Config::Key CYW955913Config::kConfigKey_HardwareVersion       = { kConfigNamespace_ChipFactory, "hardware-ver" };
const CYW955913Config::Key CYW955913Config::kConfigKey_ManufacturingDate     = { kConfigNamespace_ChipFactory, "mfg-date" };
const CYW955913Config::Key CYW955913Config::kConfigKey_SetupPinCode          = { kConfigNamespace_ChipFactory, "pin-code" };
const CYW955913Config::Key CYW955913Config::kConfigKey_SetupDiscriminator    = { kConfigNamespace_ChipFactory, "discriminator" };
const CYW955913Config::Key CYW955913Config::kConfigKey_Spake2pIterationCount = { kConfigNamespace_ChipFactory, "iteration-count" };
const CYW955913Config::Key CYW955913Config::kConfigKey_Spake2pSalt           = { kConfigNamespace_ChipFactory, "salt" };
const CYW955913Config::Key CYW955913Config::kConfigKey_Spake2pVerifier       = { kConfigNamespace_ChipFactory, "verifier" };

// Keys stored in the chip-config namespace
const CYW955913Config::Key CYW955913Config::kConfigKey_ServiceConfig      = { kConfigNamespace_ChipConfig, "service-config" };
const CYW955913Config::Key CYW955913Config::kConfigKey_PairedAccountId    = { kConfigNamespace_ChipConfig, "account-id" };
const CYW955913Config::Key CYW955913Config::kConfigKey_ServiceId          = { kConfigNamespace_ChipConfig, "service-id" };
const CYW955913Config::Key CYW955913Config::kConfigKey_LastUsedEpochKeyId = { kConfigNamespace_ChipConfig, "last-ek-id" };
const CYW955913Config::Key CYW955913Config::kConfigKey_FailSafeArmed      = { kConfigNamespace_ChipConfig, "fail-safe-armed" };
const CYW955913Config::Key CYW955913Config::kConfigKey_WiFiStationSecType = { kConfigNamespace_ChipConfig, "sta-sec-type" };
const CYW955913Config::Key CYW955913Config::kConfigKey_RegulatoryLocation = { kConfigNamespace_ChipConfig, "regulatory-location" };
const CYW955913Config::Key CYW955913Config::kConfigKey_CountryCode        = { kConfigNamespace_ChipConfig, "country-code" };
const CYW955913Config::Key CYW955913Config::kConfigKey_ConfigurationVersion = { kConfigNamespace_ChipConfig, "configuration-version" };
const CYW955913Config::Key CYW955913Config::kConfigKey_WiFiSSID           = { kConfigNamespace_ChipConfig, "wifi-ssid" };
const CYW955913Config::Key CYW955913Config::kConfigKey_WiFiPassword       = { kConfigNamespace_ChipConfig, "wifi-password" };
const CYW955913Config::Key CYW955913Config::kConfigKey_WiFiSecurity       = { kConfigNamespace_ChipConfig, "wifi-security" };
const CYW955913Config::Key CYW955913Config::kConfigKey_WiFiMode           = { kConfigNamespace_ChipConfig, "wifimode" };
const CYW955913Config::Key CYW955913Config::kConfigKey_UniqueId           = { kConfigNamespace_ChipConfig, "unique-id" };
const CYW955913Config::Key CYW955913Config::kConfigKey_LockUser           = { kConfigNamespace_ChipConfig, "lock-user" };
const CYW955913Config::Key CYW955913Config::kConfigKey_Credential         = { kConfigNamespace_ChipConfig, "credential" };
const CYW955913Config::Key CYW955913Config::kConfigKey_LockUserName       = { kConfigNamespace_ChipConfig, "lock-user-name" };
const CYW955913Config::Key CYW955913Config::kConfigKey_CredentialData     = { kConfigNamespace_ChipConfig, "credential-data" };
const CYW955913Config::Key CYW955913Config::kConfigKey_UserCredentials    = { kConfigNamespace_ChipConfig, "user-credentials" };
const CYW955913Config::Key CYW955913Config::kConfigKey_WeekDaySchedules   = { kConfigNamespace_ChipConfig, "weekday-schedules" };
;
const CYW955913Config::Key CYW955913Config::kConfigKey_YearDaySchedules = { kConfigNamespace_ChipConfig, "yearday-schedules" };
;
const CYW955913Config::Key CYW955913Config::kConfigKey_HolidaySchedules = { kConfigNamespace_ChipConfig, "holiday-schedules" };
;

// Keys stored in the Chip-counters namespace
const CYW955913Config::Key CYW955913Config::kCounterKey_RebootCount           = { kConfigNamespace_ChipCounters, "reboot-count" };
const CYW955913Config::Key CYW955913Config::kCounterKey_UpTime                = { kConfigNamespace_ChipCounters, "up-time" };
const CYW955913Config::Key CYW955913Config::kCounterKey_TotalOperationalHours = { kConfigNamespace_ChipCounters, "total-hours" };

CHIP_ERROR CYW955913Config::ReadConfigValue(Key key, bool & val)
{
    bool in;
    char key_str[KV_MAX_KEY_SIZE] = { 0 };
    key.to_str(key_str, KV_MAX_KEY_SIZE);
    CHIP_ERROR err = PersistedStorage::KeyValueStoreMgr().Get(key_str, static_cast<void *>(&in), sizeof(bool));
    val            = in;
    if (err == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND)
    {
        err = CHIP_DEVICE_ERROR_CONFIG_NOT_FOUND;
    }
    return err;
}

CHIP_ERROR CYW955913Config::ReadConfigValue(Key key, uint32_t & val)
{
    uint32_t in;
    char key_str[KV_MAX_KEY_SIZE] = { 0 };
    key.to_str(key_str, KV_MAX_KEY_SIZE);
    CHIP_ERROR err = PersistedStorage::KeyValueStoreMgr().Get(key_str, static_cast<void *>(&in), 4);
    val            = in;
    if (err == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND)
    {
        err = CHIP_DEVICE_ERROR_CONFIG_NOT_FOUND;
    }
    return err;
}

CHIP_ERROR CYW955913Config::ReadConfigValue(Key key, uint64_t & val)
{
    uint64_t in;
    char key_str[KV_MAX_KEY_SIZE] = { 0 };
    key.to_str(key_str, KV_MAX_KEY_SIZE);
    CHIP_ERROR err = PersistedStorage::KeyValueStoreMgr().Get(key_str, static_cast<void *>(&in), 8);
    val            = in;
    if (err == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND)
    {
        err = CHIP_DEVICE_ERROR_CONFIG_NOT_FOUND;
    }
    return err;
}

CHIP_ERROR CYW955913Config::ReadConfigValueStr(Key key, char * buf, size_t bufSize, size_t & outLen)
{
    char key_str[KV_MAX_KEY_SIZE] = { 0 };
    key.to_str(key_str, KV_MAX_KEY_SIZE);
    CHIP_ERROR err = PersistedStorage::KeyValueStoreMgr().Get(key_str, buf, bufSize, &outLen);
    if (err == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND)
    {
        err = CHIP_DEVICE_ERROR_CONFIG_NOT_FOUND;
    }
    return err;
}

CHIP_ERROR CYW955913Config::ReadConfigValueBin(Key key, uint8_t * buf, size_t bufSize, size_t & outLen)
{
    char key_str[KV_MAX_KEY_SIZE] = { 0 };
    key.to_str(key_str, KV_MAX_KEY_SIZE);
    CHIP_ERROR err = PersistedStorage::KeyValueStoreMgr().Get(key_str, buf, bufSize, &outLen);
    if (err == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND)
    {
        err = CHIP_DEVICE_ERROR_CONFIG_NOT_FOUND;
    }
    return err;
}

CHIP_ERROR CYW955913Config::WriteConfigValue(Key key, bool val)
{
    char key_str[KV_MAX_KEY_SIZE] = { 0 };
    key.to_str(key_str, KV_MAX_KEY_SIZE);
    return PersistedStorage::KeyValueStoreMgr().Put(key_str, static_cast<void *>(&val), sizeof(bool));
}

CHIP_ERROR CYW955913Config::WriteConfigValue(Key key, uint32_t val)
{
    char key_str[KV_MAX_KEY_SIZE] = { 0 };
    key.to_str(key_str, KV_MAX_KEY_SIZE);
    return PersistedStorage::KeyValueStoreMgr().Put(key_str, static_cast<void *>(&val), 4);
}

CHIP_ERROR CYW955913Config::WriteConfigValue(Key key, uint64_t val)
{
    char key_str[KV_MAX_KEY_SIZE] = { 0 };
    key.to_str(key_str, KV_MAX_KEY_SIZE);
    return PersistedStorage::KeyValueStoreMgr().Put(key_str, static_cast<void *>(&val), 8);
}

CHIP_ERROR CYW955913Config::WriteConfigValueStr(Key key, const char * str)
{
    size_t size                            = strlen(str) + 1;
    char key_str[KV_MAX_KEY_SIZE] = { 0 };
    key.to_str(key_str, KV_MAX_KEY_SIZE);
    return PersistedStorage::KeyValueStoreMgr().Put(key_str, str, size);
}

CHIP_ERROR CYW955913Config::WriteConfigValueStr(Key key, const char * str, size_t strLen)
{
    char key_str[KV_MAX_KEY_SIZE] = { 0 };
    key.to_str(key_str, KV_MAX_KEY_SIZE);
    return PersistedStorage::KeyValueStoreMgr().Put(key_str, str, strLen);
}
CHIP_ERROR CYW955913Config::WriteConfigValueBin(Key key, const uint8_t * data, size_t dataLen)
{
    char key_str[KV_MAX_KEY_SIZE] = { 0 };
    key.to_str(key_str, KV_MAX_KEY_SIZE);
    return PersistedStorage::KeyValueStoreMgr().Put(key_str, data, dataLen);
}

CHIP_ERROR CYW955913Config::ClearConfigValue(Key key)
{
    char key_str[KV_MAX_KEY_SIZE] = { 0 };
    key.to_str(key_str, KV_MAX_KEY_SIZE);
    return PersistedStorage::KeyValueStoreMgr().Delete(key_str);
}

bool CYW955913Config::ConfigValueExists(Key key)
{
    char key_str[KV_MAX_KEY_SIZE] = { 0 };
    key.to_str(key_str, KV_MAX_KEY_SIZE);
    if (PersistedStorage::KeyValueStoreMgr().Get(key_str, NULL, 0) == CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND)
    {
        return false;
    }

    return true;
}

// Clear out keys in config namespace
CHIP_ERROR CYW955913Config::FactoryResetConfig(void)
{
    CHIP_ERROR err            = CHIP_NO_ERROR;
    const Key * config_keys[] = { &kConfigKey_ServiceConfig,      &kConfigKey_PairedAccountId, &kConfigKey_ServiceId,
                                  &kConfigKey_LastUsedEpochKeyId, &kConfigKey_FailSafeArmed,   &kConfigKey_WiFiStationSecType,
                                  &kConfigKey_WiFiSSID,           &kConfigKey_WiFiPassword,    &kConfigKey_WiFiSecurity,
                                  &kConfigKey_WiFiMode,           &kConfigKey_SoftwareVersion };

    for (uint32_t i = 0; i < (sizeof(config_keys) / sizeof(config_keys[0])); i++)
    {
        err = ClearConfigValue(*config_keys[i]);
        // Something unexpected happened
        if (err != CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND && err != CHIP_NO_ERROR)
        {
            return err;
        }
    }

    // Erase all key-values including fabric info.
    err = PersistedStorage::KeyValueStoreMgrImpl().Erase();
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(DeviceLayer, "Clear Key-Value Storage failed");
    }

    return CHIP_NO_ERROR;
}

void CYW955913Config::RunConfigUnitTest() {}

} // namespace Internal
} // namespace DeviceLayer
} // namespace chip
