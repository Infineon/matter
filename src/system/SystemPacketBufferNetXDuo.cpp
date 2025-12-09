/*
 *
 *    Copyright (c) 2024 Project CHIP Authors
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
 *      This file defines the member functions and private data for
 *      the chip::System::PacketBuffer class, which provides the
 *      mechanisms for manipulating packets of octet-serialized
 *      data.
 */
// Include standard C library limit macros
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

// Include module header
#include <system/SystemPacketBuffer.h>

// Include local headers
#include <lib/support/CodeUtils.h>
#include <lib/support/SafeInt.h>
#include <lib/support/logging/CHIPLogging.h>
#include <system/SystemFaultInjection.h>
#include <system/SystemMutex.h>
#include <system/SystemStats.h>

#include <stdint.h>

#include <limits.h>
#include <limits>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <utility>

#if !CHIP_SYSTEM_CONFIG_USE_NETXDUO
#error "Unsupported configuration"
#endif // CHIP_SYSTEM_CONFIG_USE_NETXDUO

#include <nx_api.h>
#include <packet_pool_utils.h>

#if NX_DISABLE_PACKET_CHAIN
#error "Packet chain feature must be enabled"
#endif

namespace chip {
namespace System {

// Pointer to the packet pool for allocating packets
static NX_PACKET_POOL * sPacketPool;

#if !CHIP_SYSTEM_CONFIG_NO_LOCKING
static Mutex sBufferPoolMutex;

#define LOCK_BUF_POOL()                                                                                                            \
    do                                                                                                                             \
    {                                                                                                                              \
        sBufferPoolMutex.Lock();                                                                                                   \
    } while (0)
#define UNLOCK_BUF_POOL()                                                                                                          \
    do                                                                                                                             \
    {                                                                                                                              \
        sBufferPoolMutex.Unlock();                                                                                                 \
    } while (0)
#endif // !CHIP_SYSTEM_CONFIG_NO_LOCKING

void PacketBuffer::SetStart(uint8_t * aNewStart)
{
    uint8_t * const kStart = this->nx_packet_data_start;
    uint8_t * const kEnd   = this->nx_packet_data_end;
    ptrdiff_t len = this->nx_packet_append_ptr - this->nx_packet_prepend_ptr;

    if (aNewStart < kStart)
        aNewStart = kStart;
    else if (aNewStart > kEnd)
        aNewStart = kEnd;

    ptrdiff_t lDelta = aNewStart - static_cast<uint8_t *>(this->nx_packet_prepend_ptr);
    if (lDelta > len)
        lDelta = len;

    this->nx_packet_length       = static_cast<ULONG>(static_cast<ptrdiff_t>(this->nx_packet_length) - lDelta);
    this->nx_packet_prepend_ptr  = static_cast<UCHAR *>(aNewStart);
}

void PacketBuffer::SetDataLength(size_t aNewLen, PacketBuffer * aChainHead)
{
    const size_t kMaxDataLen = this->MaxDataLength();
    ptrdiff_t len = this->nx_packet_append_ptr - this->nx_packet_prepend_ptr;

    if (aNewLen > kMaxDataLen)
        aNewLen = kMaxDataLen;

    ptrdiff_t lDelta = static_cast<ptrdiff_t>(aNewLen) - len;

    this->nx_packet_append_ptr = this->nx_packet_prepend_ptr + aNewLen;
    this->nx_packet_length     = static_cast<uint16_t>(this->nx_packet_length + lDelta);

    // SetDataLength is often called after a client finished writing to the buffer,
    // so it's a good time to check for possible corruption.
    Check(this);

    while (aChainHead != nullptr && aChainHead != this)
    {
        Check(aChainHead);
        aChainHead->nx_packet_length = static_cast<uint16_t>(aChainHead->nx_packet_length + lDelta);
        aChainHead          = aChainHead->ChainedBuffer();
    }
}

size_t PacketBuffer::MaxDataLength() const
{
    return static_cast<size_t>(AllocSize() - ReservedSize());
}

size_t PacketBuffer::AvailableDataLength() const
{
    return static_cast<size_t>(this->MaxDataLength() - this->DataLength());
}

uint16_t PacketBuffer::ReservedSize() const
{
    // Cast to uint16_t is safe because Start() always points to "after"
    // ReserveStart().  At least when the payload is stored inline.
    return static_cast<uint16_t>(Start() - ReserveStart());
}

uint8_t * PacketBuffer::ReserveStart()
{
    return static_cast<uint8_t *>(this->nx_packet_data_start);
}

const uint8_t * PacketBuffer::ReserveStart() const
{
    return static_cast<const uint8_t *>(this->nx_packet_data_start);
}

void PacketBuffer::AddToEnd(PacketBufferHandle && aPacketHandle)
{
    // Ownership of aPacketHandle's buffer is transferred to the end of the chain.
    PacketBuffer * aPacket = std::move(aPacketHandle).UnsafeRelease();
    ptrdiff_t len = aPacket->nx_packet_append_ptr - aPacket->nx_packet_prepend_ptr;

    PacketBuffer * lCursor = this;

    while (true)
    {
        ULONG old_total_length    = lCursor->nx_packet_length;
        lCursor->nx_packet_length = lCursor->nx_packet_length + len;
        VerifyOrDieWithMsg(lCursor->nx_packet_length >= old_total_length, chipSystemLayer, "buffer chain too large");
        if (!lCursor->HasChainedBuffer())
        {
            lCursor->nx_packet_next = aPacket;
            break;
        }

        lCursor = lCursor->ChainedBuffer();
    }

    this->nx_packet_last = aPacket;
}

void PacketBuffer::CompactHead()
{
    uint8_t * const kStart = ReserveStart();

    if (this->nx_packet_prepend_ptr != kStart)
    {
        ptrdiff_t len = this->nx_packet_append_ptr - this->nx_packet_prepend_ptr;

        memmove(kStart, this->nx_packet_prepend_ptr, len);
        this->nx_packet_prepend_ptr = kStart;
        this->nx_packet_append_ptr = this->nx_packet_prepend_ptr + len;
    }

    size_t lAvailLength = this->AvailableDataLength();

    while (lAvailLength > 0 && HasChainedBuffer())
    {
        PacketBuffer & lNextPacket = *ChainedBuffer();
        VerifyOrDieWithMsg(lNextPacket.nx_packet_reserved == 1, chipSystemLayer, "next buffer %p is not exclusive to this chain", &lNextPacket);

        size_t lMoveLength = static_cast<size_t>(lNextPacket.nx_packet_append_ptr - lNextPacket.nx_packet_prepend_ptr);
        if (lMoveLength > lAvailLength)
            lMoveLength = lAvailLength;

        memcpy(static_cast<uint8_t *>(this->nx_packet_append_ptr), lNextPacket.nx_packet_prepend_ptr, lMoveLength);

        lNextPacket.nx_packet_prepend_ptr = static_cast<uint8_t *>(lNextPacket.nx_packet_prepend_ptr) + lMoveLength;
        this->nx_packet_append_ptr        = this->nx_packet_append_ptr + lMoveLength;
        lAvailLength                      = static_cast<size_t>(lAvailLength - lMoveLength);

        if (lNextPacket.nx_packet_prepend_ptr == lNextPacket.nx_packet_append_ptr)
            this->nx_packet_next = this->FreeHead(&lNextPacket);
    }
}

void PacketBuffer::ConsumeHead(size_t aConsumeLength)
{
    size_t len = static_cast<size_t>(this->nx_packet_append_ptr - this->nx_packet_prepend_ptr);

    if (aConsumeLength > len)
        aConsumeLength = len;
    this->nx_packet_prepend_ptr = static_cast<uint8_t *>(this->nx_packet_prepend_ptr) + aConsumeLength;
    this->nx_packet_length      = this->nx_packet_length - aConsumeLength;
}

/**
 * Consume data in a chain of buffers.
 *
 * Consume data in a chain of buffers starting with the current buffer and proceeding through the remaining buffers in the
 * chain. Each buffer that is completely consumed is freed and the function returns the first buffer (if any) containing the
 * remaining data. The current buffer must be the head of the buffer chain.
 *
 *  @param[in] aConsumeLength - number of bytes to consume from the current chain.
 *
 *  @return the first buffer from the current chain that contains any remaining data.  If no data remains, nullptr is returned.
 */
PacketBuffer * PacketBuffer::Consume(size_t aConsumeLength)
{
    PacketBuffer * lPacket = this;

    while (lPacket != nullptr && aConsumeLength > 0)
    {
        const size_t kLength = lPacket->DataLength();

        if (aConsumeLength >= kLength)
        {
            lPacket        = PacketBuffer::FreeHead(lPacket);
            aConsumeLength = static_cast<size_t>(aConsumeLength - kLength);
        }
        else
        {
            lPacket->ConsumeHead(aConsumeLength);
            break;
        }
    }

    return lPacket;
}

CHIP_ERROR PacketBuffer::Read(uint8_t * aDestination, size_t aReadLength) const
{
    const PacketBuffer * lPacket = this;

    if (aReadLength > TotalLength())
    {
        return CHIP_ERROR_BUFFER_TOO_SMALL;
    }
    while (aReadLength > 0)
    {
        if (lPacket == nullptr)
        {
            // TotalLength() or an individual buffer's DataLength() must have been wrong.
            return CHIP_ERROR_INTERNAL;
        }
        size_t lToReadFromCurrentBuf = lPacket->DataLength();
        if (aReadLength < lToReadFromCurrentBuf)
        {
            lToReadFromCurrentBuf = aReadLength;
        }
        memcpy(aDestination, lPacket->Start(), lToReadFromCurrentBuf);
        aDestination += lToReadFromCurrentBuf;
        aReadLength -= lToReadFromCurrentBuf;
        lPacket = lPacket->ChainedBuffer();
    }
    return CHIP_NO_ERROR;
}

bool PacketBuffer::EnsureReservedSize(uint16_t aReservedSize)
{
    const uint16_t kCurrentReservedSize = this->ReservedSize();
    if (aReservedSize <= kCurrentReservedSize)
        return true;

    size_t len = static_cast<size_t>(this->nx_packet_append_ptr - this->nx_packet_prepend_ptr);
    if ((aReservedSize + len) > this->AllocSize())
        return false;

    // Cast is safe because aReservedSize > kCurrentReservedSize.
    const uint16_t kMoveLength = static_cast<uint16_t>(aReservedSize - kCurrentReservedSize);
    memmove(static_cast<uint8_t *>(this->nx_packet_prepend_ptr) + kMoveLength, this->nx_packet_prepend_ptr, len);
    this->nx_packet_prepend_ptr = static_cast<uint8_t *>(this->nx_packet_prepend_ptr) + kMoveLength;
    this->nx_packet_append_ptr  = static_cast<uint8_t *>(this->nx_packet_append_ptr) + kMoveLength;

    return true;
}

bool PacketBuffer::AlignPayload(uint16_t aAlignBytes)
{
    if (aAlignBytes == 0)
        return false;

    const uint16_t kPayloadOffset = static_cast<uint16_t>(reinterpret_cast<uintptr_t>(this->nx_packet_prepend_ptr) % aAlignBytes);

    if (kPayloadOffset == 0)
        return true;

    // Cast is safe because by construction kPayloadOffset < aAlignBytes.
    const uint16_t kPayloadShift = static_cast<uint16_t>(aAlignBytes - kPayloadOffset);

    if (!CanCastTo<uint16_t>(this->ReservedSize() + kPayloadShift))
    {
        return false;
    }

    return (this->EnsureReservedSize(static_cast<uint16_t>(this->ReservedSize() + kPayloadShift)));
}

/**
 * Increment the reference count of the current buffer.
 */
void PacketBuffer::AddRef()
{
    LOCK_BUF_POOL();
    VerifyOrDieWithMsg(this->nx_packet_reserved < std::numeric_limits<decltype(this->nx_packet_reserved)>::max(), chipSystemLayer,
                       "packet buffer refcount overflow");
    ++this->nx_packet_reserved;
    UNLOCK_BUF_POOL();
}

PacketBufferHandle PacketBufferHandle::New(size_t aAvailableSize, uint16_t aReservedSize)
{
    // Adding three 16-bit-int sized numbers together will never overflow
    // assuming int is at least 32 bits.
    static_assert(INT_MAX >= INT32_MAX, "int is not big enough");
    static_assert(PacketBuffer::kStructureSize == sizeof(PacketBuffer), "PacketBuffer size mismatch");
    static_assert(PacketBuffer::kStructureSize < UINT16_MAX, "Check for overflow more carefully");
    static_assert(SIZE_MAX >= INT_MAX, "Our additions might not fit in size_t");
    static_assert(PacketBuffer::kMaxSizeWithoutReserve <= UINT16_MAX, "PacketBuffer may have size not fitting uint16_t");

    // When `aAvailableSize` fits in uint16_t (as tested below) and size_t is at least 32 bits (as asserted above),
    // these additions will not overflow.
    const size_t lAllocSize = aReservedSize + aAvailableSize;
    const size_t lBlockSize = PacketBuffer::kStructureSize + lAllocSize;
    PacketBuffer * lPacket;

    CHIP_SYSTEM_FAULT_INJECT(FaultInjection::kFault_PacketBufferNew, return PacketBufferHandle());

    if (aAvailableSize > UINT16_MAX || lAllocSize > PacketBuffer::kMaxSizeWithoutReserve || lBlockSize > UINT16_MAX)
    {
        ChipLogError(chipSystemLayer, "PacketBuffer: allocation too large.");
        return PacketBufferHandle();
    }

    if (sPacketPool == nullptr)
    {
        // We need to get the pointer to the packet pool to use here.
        sPacketPool = netxduo_get_packet_pool(NETXDUO_TX_POOL);
        if (sPacketPool == nullptr)
        {
            ChipLogError(chipSystemLayer, "PacketBuffer: no packet pool.");
            return PacketBufferHandle();
        }
    }

    UINT status = nx_packet_allocate(sPacketPool, reinterpret_cast<NX_PACKET**>(&lPacket), static_cast<ULONG>(aReservedSize), NX_NO_WAIT);
    if (status != NX_SUCCESS)
    {
        ChipLogError(chipSystemLayer, "PacketBuffer: pool EMPTY.");
        return PacketBufferHandle();
    }
    SYSTEM_STATS_INCREMENT(chip::System::Stats::kSystemLayer_NumPacketBufs);

    lPacket->nx_packet_reserved = 1;

#if !CHIP_SYSTEM_CONFIG_NO_LOCKING && CHIP_SYSTEM_CONFIG_THREADX_LOCKING
    if (!sBufferPoolMutex.isInitialized())
    {
        Mutex::Init(sBufferPoolMutex);
    }
#endif

    return PacketBufferHandle(lPacket);
}

PacketBufferHandle PacketBufferHandle::NewWithData(const void * aData, size_t aDataSize, size_t aAdditionalSize,
                                                   uint16_t aReservedSize)
{
    if (aDataSize > UINT16_MAX)
    {
        ChipLogError(chipSystemLayer, "PacketBuffer: allocation too large.");
        return PacketBufferHandle();
    }
    // Since `aDataSize` fits in uint16_t, the sum `aDataSize + aAdditionalSize` will not overflow.
    // `New()` will only return a non-null buffer if the total allocation size does not overflow.
    PacketBufferHandle buffer = New(aDataSize + aAdditionalSize, aReservedSize);
    if (buffer.mBuffer != nullptr)
    {
        nx_packet_data_append(buffer.mBuffer, const_cast<void *>(aData), static_cast<ULONG>(aDataSize), sPacketPool, NX_NO_WAIT);
    }
    return buffer;
}

/**
 * Free all packet buffers in a chain.
 *
 *  Decrement the reference count to all the buffers in the current chain. If the reference count reaches 0, the respective buffers
 *  are freed or returned to allocation pools as appropriate. As a rule, users should treat this method as an equivalent of
 *  `free()` function and not use the argument after the call.
 *
 *  @param[in] aPacket - packet buffer to be freed.
 */
void PacketBuffer::Free(PacketBuffer * aPacket)
{
    LOCK_BUF_POOL();

    while (aPacket != nullptr)
    {
        PacketBuffer * lNextPacket = aPacket->ChainedBuffer();

        VerifyOrDieWithMsg(aPacket->nx_packet_reserved > 0, chipSystemLayer, "SystemPacketBuffer::Free: aPacket->ref = 0");

        aPacket->nx_packet_reserved--;
        if (aPacket->nx_packet_reserved == 0)
        {
            SYSTEM_STATS_DECREMENT(chip::System::Stats::kSystemLayer_NumPacketBufs);

            // Need to clear the next pointer as nx_packet_release will traverse the entire chain.

            NX_PACKET * packet = reinterpret_cast<NX_PACKET *>(aPacket);
            packet->nx_packet_next = NULL;
            nx_packet_release(packet);

            aPacket = lNextPacket;
        }
        else
        {
            aPacket = nullptr;
        }
    }

    UNLOCK_BUF_POOL();
}

/**
 * Clear content of the packet buffer.
 *
 * This method is called by Free(), before the buffer is released to the free buffer pool.
 */
void PacketBuffer::Clear()
{
    nx_packet_length = 0;
    nx_packet_prepend_ptr = nx_packet_data_start;
    nx_packet_append_ptr  = nx_packet_data_start;
}

/**
 * Free the first buffer in a chain, returning a pointer to the remaining buffers.
 `*
 *  @note When the buffer chain is referenced by multiple callers, `FreeHead()` will detach the head, but will not forcibly
 *  deallocate the head buffer.
 *
 *  @param[in] aPacket - buffer chain.
 *
 *  @return packet buffer chain consisting of the tail of the input buffer (may be \c nullptr).
 */
PacketBuffer * PacketBuffer::FreeHead(PacketBuffer * aPacket)
{
    PacketBuffer * lNextPacket = aPacket->ChainedBuffer();
    aPacket->nx_packet_next    = nullptr;

    ptrdiff_t len = aPacket->nx_packet_append_ptr - aPacket->nx_packet_prepend_ptr;
    ULONG new_total_len = aPacket->nx_packet_length - len;

    PacketBuffer::Free(aPacket);

    // If there are remaining packets in the chain, update the length.
    if (lNextPacket != nullptr)
    {
        lNextPacket->nx_packet_length = new_total_len;
    }
    return lNextPacket;
}

PacketBufferHandle PacketBufferHandle::PopHead()
{
    PacketBuffer * head = mBuffer;

    // This takes ownership from the `next` link.
    mBuffer = mBuffer->ChainedBuffer();

    ULONG old_packet_len   = head->nx_packet_length;
    head->nx_packet_next   = nullptr;
    head->nx_packet_length = static_cast<ULONG>(head->nx_packet_append_ptr - head->nx_packet_prepend_ptr);

    if (mBuffer != nullptr)
    {
        // Set the length of the remaining chain.
        mBuffer->nx_packet_length = old_packet_len - head->nx_packet_length;
    }

    // The returned handle takes ownership from this.
    return PacketBufferHandle(head);
}

PacketBuffer * PacketBufferHandle::PopHeadBuffer()
{
    PacketBuffer * head = mBuffer;

    // This takes ownership from the `next` link.
    mBuffer = mBuffer->ChainedBuffer();

    ULONG old_packet_len   = head->nx_packet_length;
    head->nx_packet_next   = nullptr;
    head->nx_packet_length = static_cast<ULONG>(head->nx_packet_append_ptr - head->nx_packet_prepend_ptr);

    if (mBuffer != nullptr)
    {
        // Set the length of the remaining chain.
        mBuffer->nx_packet_length = old_packet_len - head->nx_packet_length;
    }

    // The caller takes ownership from this.
    return head;
}

PacketBufferHandle PacketBufferHandle::CloneData() const
{
    PacketBufferHandle cloneHead;

    // nx_packet_copy will copy the entire chain
    NX_PACKET * clonePacket;
    nx_packet_copy(mBuffer, &clonePacket, sPacketPool, NX_NO_WAIT);
    if (clonePacket == nullptr)
    {
        return PacketBufferHandle();
    }

    for (PacketBuffer * packet = reinterpret_cast<PacketBuffer *>(clonePacket); packet != nullptr; packet = packet->ChainedBuffer())
    {

        PacketBufferHandle clone = PacketBufferHandle(packet);
        if (clone.IsNull())
        {
            return PacketBufferHandle();
        }

        clone.mBuffer->nx_packet_reserved = 1;

        if (cloneHead.IsNull())
        {
            cloneHead = std::move(clone);
        }
        else
        {
            cloneHead->AddToEnd(std::move(clone));
        }
    }

    return cloneHead;
}

} // namespace System

namespace Encoding {

System::PacketBufferHandle PacketBufferWriterUtil::Finalize(BufferWriter & aBufferWriter, System::PacketBufferHandle & aPacket)
{
    if (!aPacket.IsNull() && aBufferWriter.Fit())
    {
        // Since mPacket was successfully allocated to hold the maximum length,
        // we know that the actual length fits in a uint16_t.
        aPacket->SetDataLength(static_cast<uint16_t>(aBufferWriter.Needed()));
    }
    else
    {
        aPacket = nullptr;
    }
    aBufferWriter = Encoding::BufferWriter(nullptr, 0);
    return std::move(aPacket);
}

} // namespace Encoding
} // namespace chip
