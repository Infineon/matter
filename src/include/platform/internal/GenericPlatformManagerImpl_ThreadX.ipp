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
 *          Contains non-inline method definitions for the
 *          GenericPlatformManagerImpl_ThreadX<> template.
 */

#ifndef GENERIC_PLATFORM_MANAGER_IMPL_THREADX_CPP
#define GENERIC_PLATFORM_MANAGER_IMPL_THREADX_CPP

#include <platform/PlatformManager.h>
#include <platform/internal/CHIPDeviceLayerInternal.h>
#include <platform/internal/GenericPlatformManagerImpl_ThreadX.h>

#include <lib/support/CodeUtils.h>

// Include the non-inline definitions for the GenericPlatformManagerImpl<> template,
// from which the GenericPlatformManagerImpl_ThreadX<> template inherits.
#include <platform/internal/GenericPlatformManagerImpl.ipp>

namespace chip {
namespace DeviceLayer {
namespace Internal {

template <class ImplClass>
CHIP_ERROR GenericPlatformManagerImpl_ThreadX<ImplClass>::_InitChipStack(void)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    UINT tx_status = TX_SUCCESS;
    UCHAR *queue_buffer;

    mNextTimerBaseTime = tx_time_get();
    mNextTimerDurationTicks = 0;
    mChipTimerActive = false;

    // We support calling Shutdown followed by InitChipStack, because some tests
    // do that.  To keep things simple for existing consumers, we keep not
    // destroying our lock and queue in shutdown, but rather check whether they
    // already exist here before trying to create them.

    if (mChipStackLock.tx_mutex_id == TX_CLEAR_ID)
    {
        tx_status = tx_mutex_create(&mChipStackLock, (char *)"chip stack lock", TX_INHERIT);

        if (tx_status != TX_SUCCESS)
        {
            ChipLogError(DeviceLayer, "Failed to create CHIP stack lock");
            err = CHIP_ERROR_NO_MEMORY;
        }
    }

    if (mChipEventQueue.tx_queue_id == TX_CLEAR_ID)
    {
        uint32_t event_words = (sizeof(ChipDeviceEvent) + sizeof(ULONG) - 1) / sizeof(ULONG);
        queue_buffer = (UCHAR*)malloc(CHIP_DEVICE_CONFIG_MAX_EVENT_QUEUE_SIZE * event_words * sizeof(ULONG));
        if (queue_buffer == NULL)
        {
            ChipLogError(DeviceLayer, "Failed to allocate CHIP main event queue buffer");
            ExitNow(err = CHIP_ERROR_NO_MEMORY);
        }

        tx_status = tx_queue_create(&mChipEventQueue, (char *)"chip event queue", event_words, queue_buffer,
                                    CHIP_DEVICE_CONFIG_MAX_EVENT_QUEUE_SIZE * event_words * sizeof(ULONG));
        if (tx_status != TX_SUCCESS)
        {
            ChipLogError(DeviceLayer, "Failed to allocate CHIP main event queue");
            free(queue_buffer);
            ExitNow(err = CHIP_ERROR_NO_MEMORY);
        }
    }
    else
    {
        // Clear out any events that might be stuck in the queue, so we start
        // with a clean slate, as if we had just re-created the queue.
        tx_queue_flush(&mChipEventQueue);
    }

    mShouldRunEventLoop.store(false);

#if defined(CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING) && CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING
    CHIP_ERROR err = CHIP_NO_ERROR;
    if (mBackgroundEventQueue.tx_queue_id == TX_CLEAR_ID)
    {
        uint32_t event_words = (sizeof(ChipDeviceEvent) + sizeof(ULONG) - 1) / sizeof(ULONG);
        queue_buffer = (UCHAR*)malloc(CHIP_DEVICE_CONFIG_MAX_EVENT_QUEUE_SIZE * event_words * sizeof(ULONG));
        if (queue_buffer == NULL)
        {
            ChipLogError(DeviceLayer, "Failed to allocate CHIP background event queue buffer");
            ExitNow(err = CHIP_ERROR_NO_MEMORY);
        }
        tx_status = tx_queue_create(&mBackgroundEventQueue, (char *)"background event queue", event_words,
                                    queue_buffer, CHIP_DEVICE_CONFIG_MAX_EVENT_QUEUE_SIZE * event_words * sizeof(ULONG));
        if (tx_status != TX_SUCCESS)
        {
            ChipLogError(DeviceLayer, "Failed to allocate CHIP background event queue");
            free(queue_buffer);
            ExitNow(err = CHIP_ERROR_NO_MEMORY);
        }
    }
    else
    {
        tx_queue_flush(&mBackgroundEventQueue);
    }

    mShouldRunBackgroundEventLoop.store(false);
#endif

    // Call up to the base class _InitChipStack() to perform the bulk of the initialization.
    err = GenericPlatformManagerImpl<ImplClass>::_InitChipStack();
    SuccessOrExit(err);

exit:
    return err;
}

template <class ImplClass>
void GenericPlatformManagerImpl_ThreadX<ImplClass>::_LockChipStack(void)
{
    tx_mutex_get(&mChipStackLock, TX_WAIT_FOREVER);
}

template <class ImplClass>
bool GenericPlatformManagerImpl_ThreadX<ImplClass>::_TryLockChipStack(void)
{
    return tx_mutex_get(&mChipStackLock, TX_NO_WAIT) == TX_SUCCESS;
}

template <class ImplClass>
void GenericPlatformManagerImpl_ThreadX<ImplClass>::_UnlockChipStack(void)
{
    tx_mutex_put(&mChipStackLock);
}

#if CHIP_STACK_LOCK_TRACKING_ENABLED
template <class ImplClass>
bool GenericPlatformManagerImpl_ThreadX<ImplClass>::_IsChipStackLockedByCurrentThread() const
{
    // If we have not started our event loop yet, return true because in that
    // case we can't be racing against the (not yet started) event loop.
    //
    // Similarly, if mChipStackLock has not been created yet, might as well
    // return true.
    return (mEventLoopTask.tx_thread_id == TX_CLEAR_ID) || (mChipStackLock.tx_mutex_id == TX_CLEAR_ID) ||
        (mChipStackLock.tx_mutex_owner == tx_thread_identify());
}
#endif // CHIP_STACK_LOCK_TRACKING_ENABLED

template <class ImplClass>
CHIP_ERROR GenericPlatformManagerImpl_ThreadX<ImplClass>::_PostEvent(const ChipDeviceEvent * event)
{
    if (mChipEventQueue.tx_queue_id == TX_CLEAR_ID)
    {
        return CHIP_ERROR_INTERNAL;
    }
    UINT tx_status = tx_queue_send(&mChipEventQueue, (void*)event, 0);
    if (tx_status != TX_SUCCESS)
    {
        ChipLogError(DeviceLayer, "Failed to post event to CHIP Platform event queue");
        return CHIP_ERROR(chip::ChipError::Range::kOS, tx_status);
    }
    return CHIP_NO_ERROR;
}

template <class ImplClass>
void GenericPlatformManagerImpl_ThreadX<ImplClass>::_RunEventLoop(void)
{
    CHIP_ERROR err;
    ChipDeviceEvent event;
    ULONG recvBuffer[(sizeof(ChipDeviceEvent) + sizeof(ULONG) - 1) / sizeof(ULONG)];
    bool oldShouldRunEventLoop = false;

    // Lock the CHIP stack.
    StackLock lock;

    if (!mShouldRunEventLoop.compare_exchange_strong(oldShouldRunEventLoop /* expected */, true /* desired */))
    {
        ChipLogError(DeviceLayer, "Error trying to run the event loop while it is already running");
        return;
    }

    while (mShouldRunEventLoop.load())
    {
        ULONG currentTime;
        ULONG waitTime;

        // If one or more CHIP timers are active...
        if (mChipTimerActive)
        {
            // Adjust the base time and remaining duration for the next scheduled timer based on the
            // amount of time that has elapsed since it was started.
            // IF the timer's expiration time has already arrived...
            currentTime = tx_time_get();
            if (currentTime >= mNextTimerBaseTime + mNextTimerDurationTicks)
            {
                // Reset the 'timer active' flag.  This will be set to true again by _StartChipTimer()
                // if there are further timers beyond the expired one that are still active.
                mChipTimerActive = false;


                // Call into the system layer to dispatch the callback functions for all timers
                // that have expired.
                err = static_cast<System::LayerImplThreadX &>(DeviceLayer::SystemLayer()).HandlePlatformTimer();
                if (err != CHIP_NO_ERROR)
                {
                    ChipLogError(DeviceLayer, "Error handling CHIP timers: %" CHIP_ERROR_FORMAT, err.Format());
                }

                // When processing the event queue below, do not wait if the queue is empty.  Instead
                // immediately loop around and process timers again
                waitTime = 0;
            }
            else
            {
                waitTime = mNextTimerBaseTime + mNextTimerDurationTicks - currentTime;
            }
        }
        else
        {
            waitTime = TX_WAIT_FOREVER;
        }

        UINT eventReceived = TX_QUEUE_EMPTY;
        {
            // Unlock the CHIP stack, allowing other threads to enter CHIP while
            // the event loop thread is sleeping.
            StackUnlock unlock;
            eventReceived = tx_queue_receive(&mChipEventQueue, recvBuffer, waitTime);
        }

        // If an event was received, dispatch it and continue until the queue is empty.
        while (eventReceived == TX_SUCCESS)
        {
            memcpy(&event, recvBuffer, sizeof(ChipDeviceEvent));
            Impl()->DispatchEvent(&event);
            eventReceived = tx_queue_receive(&mChipEventQueue, recvBuffer, 0);
        }
    }
}

template <class ImplClass>
CHIP_ERROR GenericPlatformManagerImpl_ThreadX<ImplClass>::_StartEventLoopTask(void)
{
    mEventLoopStack = (char*)malloc(CHIP_DEVICE_CONFIG_CHIP_TASK_STACK_SIZE);
    if (mEventLoopStack != NULL)
    {
        tx_thread_create(&mEventLoopTask, (char *)CHIP_DEVICE_CONFIG_CHIP_TASK_NAME, EventLoopTaskMain,
                    reinterpret_cast<ULONG>(this), mEventLoopStack, CHIP_DEVICE_CONFIG_CHIP_TASK_STACK_SIZE,
                    CHIP_DEVICE_CONFIG_THREAD_TASK_PRIORITY, CHIP_DEVICE_CONFIG_THREAD_TASK_PRIORITY, TX_NO_TIME_SLICE, TX_AUTO_START);
    }
    return (mEventLoopTask.tx_thread_id != TX_CLEAR_ID) ? CHIP_NO_ERROR : CHIP_ERROR_NO_MEMORY;
}

template <class ImplClass>
void GenericPlatformManagerImpl_ThreadX<ImplClass>::EventLoopTaskMain(ULONG arg)
{
    ChipLogDetail(DeviceLayer, "CHIP event task running");
    reinterpret_cast<GenericPlatformManagerImpl_ThreadX<ImplClass> *>(arg)->Impl()->RunEventLoop();
}

template <class ImplClass>
CHIP_ERROR GenericPlatformManagerImpl_ThreadX<ImplClass>::_PostBackgroundEvent(const ChipDeviceEvent * event)
{
#if defined(CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING) && CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING
    if (mBackgroundEventQueue.tx_queue_id == TX_CLEAR_ID)
    {
        return CHIP_ERROR_INTERNAL;
    }
    if (!(event->Type == DeviceEventType::kCallWorkFunct || event->Type == DeviceEventType::kNoOp))
    {
        return CHIP_ERROR_INVALID_ARGUMENT;
    }
    auto status = tx_queue_send(&mBackgroundEventQueue, (void*)event, 1);
    if (status != TX_SUCCESS)
    {
        ChipLogError(DeviceLayer, "Failed to post event to CHIP background event queue");
        return CHIP_ERROR_NO_MEMORY;
    }
    return CHIP_NO_ERROR;
#else
    // Use foreground event loop for background events
    return _PostEvent(event);
#endif
}

template <class ImplClass>
void GenericPlatformManagerImpl_ThreadX<ImplClass>::_RunBackgroundEventLoop(void)
{
#if defined(CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING) && CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING
    bool oldShouldRunBackgroundEventLoop = false;

    if (!mShouldRunBackgroundEventLoop.compare_exchange_strong(oldShouldRunBackgroundEventLoop /* expected */, true /* desired */))
    {
        ChipLogError(DeviceLayer, "Error trying to run the background event loop while it is already running");
        return;
    }

    while (mShouldRunBackgroundEventLoop.load())
    {
        ChipDeviceEvent event;
        ULONG recvBuffer[(sizeof(ChipDeviceEvent) + sizeof(ULONG) - 1) / sizeof(ULONG)];
        auto eventReceived = tx_queue_receive(&mBackgroundEventQueue, recvBuffer, TX_WAIT_FOREVER) == TX_SUCCESS;
        while (eventReceived)
        {
            memcpy(&event, recvBuffer, sizeof(ChipDeviceEvent));
            Impl()->DispatchEvent(&event);
            eventReceived = tx_queue_receive(&mBackgroundEventQueue, recvBuffer, TX_WAIT_FOREVER) == TX_SUCCESS;
        }
    }
#else
    // Use foreground event loop for background events
#endif
}

template <class ImplClass>
CHIP_ERROR GenericPlatformManagerImpl_ThreadX<ImplClass>::_StartBackgroundEventLoopTask(void)
{
#if defined(CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING) && CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING
    mBackgroundEventLoopStack = (char*)malloc(CHIP_DEVICE_CONFIG_CHIP_TASK_STACK_SIZE);
    if (mBackgroundEventLoopStack != NULL)
    {
        tx_thread_create(&mBackgroundEventLoopTask, (char *)CHIP_DEVICE_CONFIG_BG_TASK_NAME, BackgroundEventLoopTaskMain,
                    reinterpret_cast<ULONG>(this), mBackgroundEventLoopStack, CHIP_DEVICE_CONFIG_CHIP_TASK_STACK_SIZE,
                    CHIP_DEVICE_CONFIG_THREAD_TASK_PRIORITY, CHIP_DEVICE_CONFIG_THREAD_TASK_PRIORITY, TX_NO_TIME_SLICE, TX_AUTO_START);
    }
    return (mBackgroundEventLoopTask.tx_thread_id != TX_CLEAR_ID) ? CHIP_NO_ERROR : CHIP_ERROR_NO_MEMORY;
#else
    // Use foreground event loop for background events
    return CHIP_NO_ERROR;
#endif
}

template <class ImplClass>
CHIP_ERROR GenericPlatformManagerImpl_ThreadX<ImplClass>::_StopBackgroundEventLoopTask(void)
{
#if defined(CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING) && CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING
    bool oldShouldRunBackgroundEventLoop = true;
    if (mShouldRunBackgroundEventLoop.compare_exchange_strong(oldShouldRunBackgroundEventLoop /* expected */, false /* desired */))
    {
        ChipDeviceEvent noop{ .Type = DeviceEventType::kNoOp };
        tx_queue_send(&mBackgroundEventQueue, (void*)&noop, 0);
    }
    return CHIP_NO_ERROR;
#else
    // Use foreground event loop for background events
    return CHIP_NO_ERROR;
#endif
}

#if defined(CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING) && CHIP_DEVICE_CONFIG_ENABLE_BG_EVENT_PROCESSING
template <class ImplClass>
void GenericPlatformManagerImpl_ThreadX<ImplClass>::BackgroundEventLoopTaskMain(void * arg)
{
    ChipLogDetail(DeviceLayer, "CHIP background task running");
    static_cast<GenericPlatformManagerImpl_ThreadX<ImplClass> *>(arg)->Impl()->RunBackgroundEventLoop();
}
#endif

template <class ImplClass>
CHIP_ERROR GenericPlatformManagerImpl_ThreadX<ImplClass>::_StartChipTimer(System::Clock::Timeout delay)
{
    mChipTimerActive = true;
    mNextTimerBaseTime = tx_time_get();
    mNextTimerDurationTicks = (System::Clock::Milliseconds64(delay).count() * TX_TIMER_TICKS_PER_SECOND) / 1000;

    // If the platform timer is being updated by a thread other than the event loop thread,
    // trigger the event loop thread to recalculate its wait time by posting a no-op event
    // to the event queue.
    if (tx_thread_identify() != &mEventLoopTask)
    {
        ChipDeviceEvent noop{ .Type = DeviceEventType::kNoOp };
        ReturnErrorOnFailure(Impl()->PostEvent(&noop));
    }

    return CHIP_NO_ERROR;
}

template <class ImplClass>
void GenericPlatformManagerImpl_ThreadX<ImplClass>::_Shutdown(void)
{
    GenericPlatformManagerImpl<ImplClass>::_Shutdown();
}

template <class ImplClass>
CHIP_ERROR GenericPlatformManagerImpl_ThreadX<ImplClass>::_StopEventLoopTask(void)
{
    mShouldRunEventLoop.store(false);
    return CHIP_NO_ERROR;
}

// Fully instantiate the generic implementation class in whatever compilation unit includes this file.
// NB: This must come after all templated class members are defined.
template class GenericPlatformManagerImpl_ThreadX<PlatformManagerImpl>;

} // namespace Internal
} // namespace DeviceLayer
} // namespace chip

#endif // GENERIC_PLATFORM_MANAGER_IMPL_THREADX_CPP
