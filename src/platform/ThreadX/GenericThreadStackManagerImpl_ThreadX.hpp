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
 *          Contains non-inline method definitions for the
 *          GenericThreadStackManagerImpl_ThreadX<> template.
 */

#ifndef GENERIC_THREAD_STACK_MANAGER_IMPL_ThreadX_IPP
#define GENERIC_THREAD_STACK_MANAGER_IMPL_ThreadX_IPP

#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/ThreadX/GenericThreadStackManagerImpl_ThreadX.h>
#include <platform/OpenThread/OpenThreadUtils.h>
#include <platform/ThreadStackManager.h>
#include <platform/internal/CHIPDeviceLayerInternal.h>

#define THREAD_STACK_EVENT (1)

namespace chip {
namespace DeviceLayer {
namespace Internal {

template <class ImplClass>
CHIP_ERROR GenericThreadStackManagerImpl_ThreadX<ImplClass>::DoInit(void)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    UINT ret = tx_mutex_create(&mThreadStackLockMutex, (char *)"stack lock mutex", TX_INHERIT);

    if (ret != TX_SUCCESS)
    {
        ChipLogError(DeviceLayer, "Failed to create Thread stack lock");
        ExitNow(err = CHIP_ERROR_NO_MEMORY);
    }

    ret = tx_event_flags_create(&mEventFlags, "thread event flag");
    if (ret != TX_SUCCESS)
    {
        ChipLogError(DeviceLayer, "Failed to create Thread event flags");
        ExitNow(err = CHIP_ERROR_NO_MEMORY);
    }
    mThreadTask.tx_thread_id = TX_CLEAR_ID;

exit:
    return err;
}

template <class ImplClass>
CHIP_ERROR GenericThreadStackManagerImpl_ThreadX<ImplClass>::_StartThreadTask(void)
{
    if (mThreadTask.tx_thread_id != TX_CLEAR_ID)
    {
        return CHIP_ERROR_INCORRECT_STATE;
    }
    UINT ret = tx_thread_create(&mThreadTask, (char *)CHIP_DEVICE_CONFIG_THREAD_TASK_NAME, ThreadTaskMain, reinterpret_cast<ULONG>(this), mThreadStack, CHIP_DEVICE_CONFIG_THREAD_TASK_STACK_SIZE, 
                                CHIP_DEVICE_CONFIG_THREAD_TASK_PRIORITY, CHIP_DEVICE_CONFIG_THREAD_TASK_PRIORITY, TX_NO_TIME_SLICE, TX_AUTO_START);
    return (ret == TX_SUCCESS) ? CHIP_NO_ERROR : CHIP_ERROR_NO_MEMORY;
}

template <class ImplClass>
void GenericThreadStackManagerImpl_ThreadX<ImplClass>::_LockThreadStack(void)
{
    tx_mutex_get(&mThreadStackLockMutex, TX_WAIT_FOREVER);
}

template <class ImplClass>
bool GenericThreadStackManagerImpl_ThreadX<ImplClass>::_TryLockThreadStack(void)
{
    return tx_mutex_get(&mThreadStackLockMutex, TX_WAIT_FOREVER) == TX_SUCCESS;
}

template <class ImplClass>
void GenericThreadStackManagerImpl_ThreadX<ImplClass>::_UnlockThreadStack(void)
{
    tx_mutex_put(&mThreadStackLockMutex)
}

template <class ImplClass>
void GenericThreadStackManagerImpl_ThreadX<ImplClass>::SignalThreadActivityPending()
{
    if (mThreadTask.tx_thread_id != TX_CLEAR_ID)
    {
        UINT ret = tx_event_flags_set(&mEventFlags, THREAD_STACK_EVENT, TX_OR);
        if (ret != TX_SUCCESS)
        {
            ChipLogError(DeviceLayer, "Failed to set thread event flags");
        }
    }
}

template <class ImplClass>
void GenericThreadStackManagerImpl_ThreadX<ImplClass>::SignalThreadActivityPendingFromISR()
{
    if (mThreadTask.tx_thread_id != TX_CLEAR_ID)
    {
        UINT ret = tx_event_flags_set(&mEventFlags, THREAD_STACK_EVENT, TX_OR);
        if (ret != TX_SUCCESS)
        {
            ChipLogError(DeviceLayer, "Failed to set thread event flags");
        }
    }
}

template <class ImplClass>
void GenericThreadStackManagerImpl_ThreadX<ImplClass>::ThreadTaskMain(void * arg)
{
    GenericThreadStackManagerImpl_ThreadX<ImplClass> * self =
        static_cast<GenericThreadStackManagerImpl_ThreadX<ImplClass> *>(arg);

    ChipLogDetail(DeviceLayer, "Thread task running");
    ULONG reveivedFlags;
    while (true)
    {
        self->Impl()->LockThreadStack();
        self->Impl()->ProcessThreadActivity();
        self->Impl()->UnlockThreadStack();
        tx_event_flags_get(&mEventFlags, THREAD_STACK_EVENT, TX_OR_CLEAR, &reveivedFlags, TX_WAIT_FOREVER);
    }
}

// Fully instantiate the generic implementation class in whatever compilation unit includes this file.
// NB: This must come after all templated class members are defined.
template class GenericThreadStackManagerImpl_ThreadX<ThreadStackManagerImpl>;

} // namespace Internal
} // namespace DeviceLayer
} // namespace chip

#endif // GENERIC_THREAD_STACK_MANAGER_IMPL_THREADX_IPP
