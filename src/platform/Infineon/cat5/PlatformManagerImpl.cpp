/*
 *
 *    Copyright (c) 2021 Project CHIP Authors
 *    Copyright (c) 2024 Infineon Technologies, Inc.
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
 *          Provides an implementation of the PlatformManager object
 *          for the CYW955913 platform.
 */
/* this file behaves like a config.h, comes first */
#include <platform/internal/CHIPDeviceLayerInternal.h>

#include <crypto/CHIPCryptoPAL.h>
#include <platform/Infineon/cat5/DiagnosticDataProviderImpl.h>
#include <platform/PlatformManager.h>
#include <platform/internal/GenericPlatformManagerImpl_ThreadX.ipp>

extern "C" {
#include <crypto_fw_accel_api.h>
}

namespace chip {
namespace DeviceLayer {

namespace Internal {
extern CHIP_ERROR InitNetxDuoCoreLock(void);
}

PlatformManagerImpl PlatformManagerImpl::sInstance;

CHIP_ERROR PlatformManagerImpl::_InitChipStack(void)
{
    CHIP_ERROR err;

    // Make sure the NetXDuo core lock has been initialized
    err = Internal::InitNetxDuoCoreLock();
    SuccessOrExit(err);

    mStartTime = System::SystemClock().GetMonotonicTimestamp();

    ReturnErrorOnFailure(chip::Crypto::add_entropy_source(GetEntropy, NULL, 16));

    // Call _InitChipStack() on the generic implementation base class
    // to finish the initialization process.
    err = Internal::GenericPlatformManagerImpl_ThreadX<PlatformManagerImpl>::_InitChipStack();
    SuccessOrExit(err);

exit:
    return err;
}

CHIP_ERROR PlatformManagerImpl::InitNetxDuoCoreLock(void)
{
    return Internal::InitNetxDuoCoreLock();
}

void PlatformManagerImpl::_Shutdown()
{
    uint64_t upTime = 0;

    if (GetDiagnosticDataProvider().GetUpTime(upTime) == CHIP_NO_ERROR)
    {
        uint32_t totalOperationalHours = 0;

        if (ConfigurationMgr().GetTotalOperationalHours(totalOperationalHours) == CHIP_NO_ERROR)
        {
            ConfigurationMgr().StoreTotalOperationalHours(totalOperationalHours + static_cast<uint32_t>(upTime / 3600));
        }
        else
        {
            ChipLogError(DeviceLayer, "Failed to get total operational hours of the Node");
        }
    }
    else
    {
        ChipLogError(DeviceLayer, "Failed to get current uptime since the Node’s last reboot");
    }
    Internal::GenericPlatformManagerImpl_ThreadX<PlatformManagerImpl>::_Shutdown();
}

int PlatformManagerImpl::GetEntropy(void * data, unsigned char * output, size_t len, size_t * olen)
{
    int32_t retval = crypto_gen_random(NULL, output, len);
    if (retval)
    {
        return -1;
    }
    *olen = len;
    return 0;
}

} // namespace DeviceLayer
} // namespace chip
