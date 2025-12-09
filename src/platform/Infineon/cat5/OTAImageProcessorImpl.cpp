/*
 *
 *    Copyright (c) 2022 Project CHIP Authors
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

#include "OTAImageProcessorImpl.h"
#include <app/clusters/ota-requestor/OTADownloader.h>
#include <app/clusters/ota-requestor/OTARequestorInterface.h>
#include <lib/support/CodeUtils.h>
#include <platform/CHIPDeviceLayer.h>

extern "C" {
#include "cy_tx_thread.h"
#include <cy_ota_api.h>
#include <cy_ota_storage_api.h>
}

cy_ota_storage_context_t ota_storage_ctx;

using namespace ::chip::DeviceLayer::Internal;

namespace chip {
namespace DeviceLayer {
#ifdef CYW955913_OTA
CHIP_ERROR OTAImageProcessorImpl::PrepareDownload()
{
    DeviceLayer::PlatformMgr().ScheduleWork(HandlePrepareDownload, reinterpret_cast<intptr_t>(this));
    return CHIP_NO_ERROR;
}

CHIP_ERROR OTAImageProcessorImpl::Finalize()
{
    DeviceLayer::PlatformMgr().ScheduleWork(HandleFinalize, reinterpret_cast<intptr_t>(this));
    return CHIP_NO_ERROR;
}

CHIP_ERROR OTAImageProcessorImpl::Apply()
{
    DeviceLayer::PlatformMgr().ScheduleWork(HandleApply, reinterpret_cast<intptr_t>(this));
    return CHIP_NO_ERROR;
}

CHIP_ERROR OTAImageProcessorImpl::Abort()
{
    DeviceLayer::PlatformMgr().ScheduleWork(HandleAbort, reinterpret_cast<intptr_t>(this));
    return CHIP_NO_ERROR;
}

CHIP_ERROR OTAImageProcessorImpl::ProcessHeader(ByteSpan & block)
{
    // Only modify the ByteSpan if the OTAImageHeaderParser is currently initialized.
    if (mHeaderParser.IsInitialized())
    {
        OTAImageHeader header;

        // AccumulateAndDecode will cause the OTAImageHeader bytes to be stored
        // in header. We don't do anything with header, however, the other
        // consequence of this call is to advance the data pointer in block. In
        // this or subsequent calls to this API, block will end up pointing at
        // the first byte after OTAImageHeader.
        CHIP_ERROR error = mHeaderParser.AccumulateAndDecode(block, header);

        // If we have not received all the bytes of the OTAImageHeader yet, that is OK.
        // Return CHIP_NO_ERROR and expect that future blocks will contain the rest.
        ReturnErrorCodeIf(error == CHIP_ERROR_BUFFER_TOO_SMALL, CHIP_NO_ERROR);

        // If there is some error other than "too small", return that so future
        // processing will be aborted.
        ReturnErrorOnFailure(error);

        mParams.totalFileBytes = header.mPayloadSize;

        // If we are here, then we have received all the OTAImageHeader bytes.
        // Calling Clear() here results in the parser state being set to
        // uninitialized. This means future calls to ProcessHeader will not
        // modify block and those future bytes will be written to the device.
        mHeaderParser.Clear();
    }

    return CHIP_NO_ERROR;
}

CHIP_ERROR OTAImageProcessorImpl::ProcessBlock(ByteSpan & block)
{
    if ((block.data() == nullptr) || block.empty())
    {
        return CHIP_ERROR_INVALID_ARGUMENT;
    }

    // Store block data for HandleProcessBlock to access
    CHIP_ERROR err = SetBlock(block);
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(SoftwareUpdate, "Cannot set block data: %" CHIP_ERROR_FORMAT, err.Format());
    }
    HandleProcessBlock(reinterpret_cast<intptr_t>(this));
    return CHIP_NO_ERROR;
}

bool OTAImageProcessorImpl::IsFirstImageRun()
{
    OTARequestorInterface * requestor = GetRequestorInstance();
    ReturnErrorCodeIf(requestor == nullptr, false);

    uint32_t currentVersion;
    ReturnErrorCodeIf(ConfigurationMgr().GetSoftwareVersion(currentVersion) != CHIP_NO_ERROR, false);

    ChipLogProgress(SoftwareUpdate, "%ld", currentVersion);
    ChipLogProgress(SoftwareUpdate, "%ld", requestor->GetTargetVersion());

    return ((requestor->GetCurrentUpdateState() == OTARequestorInterface::OTAUpdateStateEnum::kApplying) &&
            (requestor->GetTargetVersion() == currentVersion));
}

CHIP_ERROR OTAImageProcessorImpl::ConfirmCurrentImage()
{
    OTARequestorInterface * requestor = chip::GetRequestorInstance();
    if (requestor == nullptr)
    {
        return CHIP_ERROR_INTERNAL;
    }

    uint32_t currentVersion;
    ReturnErrorOnFailure(DeviceLayer::ConfigurationMgr().GetSoftwareVersion(currentVersion));
    if (currentVersion != requestor->GetTargetVersion())
    {
        return CHIP_ERROR_INCORRECT_STATE;
    }

    return CHIP_NO_ERROR;
}

void OTAImageProcessorImpl::HandlePrepareDownload(intptr_t context)
{
    auto * imageProcessor = reinterpret_cast<OTAImageProcessorImpl *>(context);
    if (imageProcessor == nullptr)
    {
        ChipLogError(SoftwareUpdate, "ImageProcessor context is null");
        return;
    }
    else if (imageProcessor->mDownloader == nullptr)
    {
        ChipLogError(SoftwareUpdate, "mDownloader is null");
        return;
    }

    /* Open storage area for storing OTA upgrade image. This will erase anything in the upgrade slot*/
    if (cy_ota_storage_open(&ota_storage_ctx) != CY_RSLT_SUCCESS)
    {
        imageProcessor->mDownloader->OnPreparedForDownload(CHIP_ERROR_OPEN_FAILED);
        return;
    }

    // init the OTAImageHeaderParser instance to indicate that we haven't yet
    // parsed the header out of the incoming image.
    imageProcessor->mHeaderParser.Init();

    imageProcessor->mDownloader->OnPreparedForDownload(CHIP_NO_ERROR);
}

void OTAImageProcessorImpl::HandleFinalize(intptr_t context)
{
    auto * imageProcessor = reinterpret_cast<OTAImageProcessorImpl *>(context);
    if (imageProcessor == nullptr)
    {
        return;
    }
    cy_ota_storage_close(&ota_storage_ctx);
    imageProcessor->ReleaseBlock();
}

void OTAImageProcessorImpl::HandleAbort(intptr_t context)
{
    auto * imageProcessor = reinterpret_cast<OTAImageProcessorImpl *>(context);
    if (imageProcessor == nullptr)
    {
        return;
    }
    /* open API will erase our flash area automatically */
    cy_ota_storage_open(&ota_storage_ctx);
    imageProcessor->ReleaseBlock();
}

void OTAImageProcessorImpl::HandleProcessBlock(intptr_t context)
{
    auto * imageProcessor = reinterpret_cast<OTAImageProcessorImpl *>(context);
    if (imageProcessor == nullptr)
    {
        ChipLogError(SoftwareUpdate, "ImageProcessor context is null");
        return;
    }
    else if (imageProcessor->mDownloader == nullptr)
    {
        ChipLogError(SoftwareUpdate, "mDownloader is null");
        return;
    }

    // The call to ProcessHeader will result in the modification of the block ByteSpan data
    // pointer if the OTAImageHeader is present in the image. The result is that only
    // the new application bytes will be written to the device in the flash_area_write calls,
    // as all bytes for the header are skipped.
    ByteSpan block = ByteSpan(imageProcessor->mBlock.data(), imageProcessor->mBlock.size());

    CHIP_ERROR error = imageProcessor->ProcessHeader(block);
    if (error != CHIP_NO_ERROR)
    {
        ChipLogError(SoftwareUpdate, "Failed to process OTA image header");
        imageProcessor->mDownloader->EndDownload(error);
        return;
    }
    // send down only the post-processed bytes from block to this call, rather than sending down
    // the original bytes from imageProcessor. The bytes in imageProcessor may include date
    // from the OTAImageHeader, which we don't want.
    cy_ota_storage_write_info_t ota_info;
    ota_info.total_size = ota_storage_ctx.total_bytes_written;
    ota_info.offset     = imageProcessor->mParams.downloadedBytes;
    ota_info.buffer     = (uint8_t *) block.data();
    ota_info.size       = (uint32_t) block.size();
    cy_rslt_t result    = cy_ota_storage_write(&ota_storage_ctx, &ota_info);

    if (result != CY_RSLT_SUCCESS)
    {
        imageProcessor->mDownloader->EndDownload(CHIP_ERROR_WRITE_FAILED);
        return;
    }

    // increment the total downloaded bytes by the potentially modified block ByteSpan size
    ota_storage_ctx.total_bytes_written += ota_info.size;
    imageProcessor->mParams.downloadedBytes += block.size();
    imageProcessor->mDownloader->FetchNextData();
}

void OTAImageProcessorImpl::HandleApply(intptr_t context)
{
    ChipLogProgress(SoftwareUpdate, "Swapping image and rebooting after 2 seconds...");
    cy_rtos_delay_milliseconds(2000);
    cy_ota_storage_switch_to_new_image(1);
    return;
}

CHIP_ERROR OTAImageProcessorImpl::SetBlock(ByteSpan & block)
{
    if (block.empty())
    {
        ReleaseBlock();
        return CHIP_NO_ERROR;
    }
    if (mBlock.size() < block.size())
    {
        if (!mBlock.empty())
        {
            ReleaseBlock();
        }
        uint8_t * mBlock_ptr = static_cast<uint8_t *>(chip::Platform::MemoryAlloc(block.size()));
        if (mBlock_ptr == nullptr)
        {
            return CHIP_ERROR_NO_MEMORY;
        }
        mBlock = MutableByteSpan(mBlock_ptr, block.size());
    }
    CHIP_ERROR err = CopySpanToMutableSpan(block, mBlock);
    if (err != CHIP_NO_ERROR)
    {
        ChipLogError(SoftwareUpdate, "Cannot copy block data: %" CHIP_ERROR_FORMAT, err.Format());
        return err;
    }
    return CHIP_NO_ERROR;
}

CHIP_ERROR OTAImageProcessorImpl::ReleaseBlock()
{
    if (mBlock.data() != nullptr)
    {
        chip::Platform::MemoryFree(mBlock.data());
    }

    mBlock = MutableByteSpan();
    return CHIP_NO_ERROR;
}
#endif

} // namespace DeviceLayer
} // namespace chip
