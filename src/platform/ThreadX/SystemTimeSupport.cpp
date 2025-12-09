/*
 *
 *    Copyright (c) 2020 Project CHIP Authors
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
 *          Provides implementations of the CHIP System Layer platform
 *          time/clock functions based on the ThreadX tick counter.
 */
/* this file behaves like a config.h, comes first */

#include <platform/internal/CHIPDeviceLayerInternal.h>

#include <lib/support/TimeUtils.h>

#include "tx_api.h"

namespace chip {
namespace System {
namespace Clock {

namespace Internal {
ClockImpl gClockImpl;
} // namespace Internal

namespace {

uint64_t sBootTimeUS = 0;

} // unnamed namespace

uint64_t ThreadXTicksSinceBoot(void) __attribute__((weak));

uint64_t ThreadXTicksSinceBoot(void)
{
    // tx_time_get will get us the total number of ticks that have occurred since the system was booted.
    return (uint64_t) tx_time_get();
}

Clock::Microseconds64 ClockImpl::GetMonotonicMicroseconds64(void)
{
    return Clock::Microseconds64((ThreadXTicksSinceBoot() * kMicrosecondsPerSecond) / TX_TIMER_TICKS_PER_SECOND);
}

Clock::Milliseconds64 ClockImpl::GetMonotonicMilliseconds64(void)
{
    return Clock::Milliseconds64((ThreadXTicksSinceBoot() * kMillisecondsPerSecond) / TX_TIMER_TICKS_PER_SECOND);
}

uint64_t GetClock_Monotonic(void)
{
    return (ThreadXTicksSinceBoot() * kMicrosecondsPerSecond) / TX_TIMER_TICKS_PER_SECOND;
}

uint64_t GetClock_MonotonicMS(void)
{
    return (ThreadXTicksSinceBoot() * kMillisecondsPerSecond) / TX_TIMER_TICKS_PER_SECOND;
}

uint64_t GetClock_MonotonicHiRes(void)
{
    return GetClock_Monotonic();
}

CHIP_ERROR ClockImpl::GetClock_RealTime(Clock::Microseconds64 & aCurTime)
{
    // TODO(19081): This platform does not properly error out if wall clock has
    //              not been set.  For now, short circuit this.
    return CHIP_ERROR_UNSUPPORTED_CHIP_FEATURE;
#if 0
    if (sBootTimeUS == 0)
    {
        return CHIP_ERROR_REAL_TIME_NOT_SYNCED;
    }
    aCurTime = Clock::Microseconds64(sBootTimeUS + GetClock_Monotonic());
    return CHIP_NO_ERROR;
#endif
}

CHIP_ERROR ClockImpl::GetClock_RealTimeMS(Clock::Milliseconds64 & aCurTime)
{
    if (sBootTimeUS == 0)
    {
        return CHIP_ERROR_REAL_TIME_NOT_SYNCED;
    }
    aCurTime = Clock::Milliseconds64((sBootTimeUS + GetClock_Monotonic()) / TX_TIMER_TICKS_PER_SECOND);
    return CHIP_NO_ERROR;
}

CHIP_ERROR ClockImpl::SetClock_RealTime(Clock::Microseconds64 aNewCurTime)
{
    uint64_t timeSinceBootUS = GetClock_Monotonic();
    if (aNewCurTime.count() > timeSinceBootUS)
    {
        sBootTimeUS = aNewCurTime.count() - timeSinceBootUS;
    }
    else
    {
        sBootTimeUS = 0;
    }
    return CHIP_NO_ERROR;
}

CHIP_ERROR InitClock_RealTime()
{
    Clock::Microseconds64 curTime =
        Clock::Microseconds64((static_cast<uint64_t>(CHIP_SYSTEM_CONFIG_VALID_REAL_TIME_THRESHOLD) * UINT64_C(1000000)));
    // Use CHIP_SYSTEM_CONFIG_VALID_REAL_TIME_THRESHOLD as the initial value of RealTime.
    // Then the RealTime obtained from GetClock_RealTime will be always valid.
    //
    // TODO(19081): This is broken because it causes the platform to report
    //              that it does have wall clock time when it actually doesn't.
    return System::SystemClock().SetClock_RealTime(curTime);
}

} // namespace Clock
} // namespace System
} // namespace chip
