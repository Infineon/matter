/*
 *
 *    Copyright (c) 2020 Project CHIP Authors
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
 *          Provides an generic implementation of PlatformManager features
 *          for use on ThreadX platforms.
 */

#pragma once

#include <platform/CHIPDeviceConfig.h>
#include <platform/internal/GenericPlatformManagerImpl.h>

#include "tx_api.h"
#include "tx_mutex.h"

#include <atomic>

namespace chip {
namespace DeviceLayer {
namespace Internal {

/**
 * Provides a generic implementation of PlatformManager features that works on ThreadX platforms.
 *
 * This template contains implementations of select features from the PlatformManager abstract
 * interface that are suitable for use on ThreadX-based platforms.  It is intended to be inherited
 * (directly or indirectly) by the PlatformManagerImpl class, which also appears as the template's
 * ImplClass parameter.
 */
template <class ImplClass>
class GenericPlatformManagerImpl_ThreadX : public GenericPlatformManagerImpl<ImplClass>
{

protected:
    ULONG mNextTimerBaseTime;
    ULONG mNextTimerDurationTicks;
    TX_MUTEX mChipStackLock;
    TX_QUEUE mChipEventQueue;

    TX_THREAD mEventLoopTask;
    bool mChipTimerActive;

#if defined(CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING) && CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING
    TX_QUEUE mBackgroundEventQueue;
    TX_THREAD mBackgroundEventLoopTask;
#endif

    // ===== Methods that implement the PlatformManager abstract interface.

    CHIP_ERROR _InitChipStack();

    void _LockChipStack(void);
    bool _TryLockChipStack(void);
    void _UnlockChipStack(void);

    CHIP_ERROR _PostEvent(const ChipDeviceEvent * event);
    void _RunEventLoop(void);
    CHIP_ERROR _StartEventLoopTask(void);
    CHIP_ERROR _StopEventLoopTask();
    CHIP_ERROR _StartChipTimer(System::Clock::Timeout duration);
    void _Shutdown(void);

#if CHIP_STACK_LOCK_TRACKING_ENABLED
    bool _IsChipStackLockedByCurrentThread() const;
#endif

    CHIP_ERROR _PostBackgroundEvent(const ChipDeviceEvent * event);
    void _RunBackgroundEventLoop(void);
    CHIP_ERROR _StartBackgroundEventLoopTask(void);
    CHIP_ERROR _StopBackgroundEventLoopTask();

private:

    // ===== Private members for use by this class only.
    inline ImplClass * Impl() { return static_cast<ImplClass *>(this); }
    static void EventLoopTaskMain(ULONG arg);
    char *mEventLoopStack = NULL;
    std::atomic<bool> mShouldRunEventLoop;

#if defined(CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING) && CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING
    static void BackgroundEventLoopTaskMain(void * arg);
    char *mBackgroundEventLoopStack = NULL;
    std::atomic<bool> mShouldRunBackgroundEventLoop;
#endif

};

// Instruct the compiler to instantiate the template only when explicitly told to do so.
extern template class GenericPlatformManagerImpl_ThreadX<PlatformManagerImpl>;

} // namespace Internal
} // namespace DeviceLayer
} // namespace chip
