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
 *          Defines platform-specific event types and data for the
 *          CHIP Device Layer on the CYW955913.
 */

#pragma once

#include <platform/CHIPDeviceEvent.h>

namespace chip {
namespace DeviceLayer {

namespace DeviceEventType {

/**
 * Enumerates platform-specific event types that are visible to the application.
 */
enum
{
    kCYW955913SystemEvent = kRange_PublicPlatformSpecific,
};

/**
 * Enumerates internal platform-specific event types.
 */
enum InternalPlatformSpecificEventTypes
{
    // TODO: maybe need remove this and handle BLEEnabledEvt direct
    //      from BLEManagerImpl::BLEManagerCallback.
    kCYW955913BLEEnabledEvt = kRange_InternalPlatformSpecific,
    kCYW955913BLEDisabledEvt
};

} // namespace DeviceEventType

/**
 * Represents platform-specific event information for the CYW955913 platform.
 */
struct ChipDevicePlatformEvent final
{
    union
    {
        struct
        {
            int32_t event_type;
        } CYW955913SystemEvent;
    };
};

} // namespace DeviceLayer
} // namespace chip
