/*
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
 *      This header file defines some packet pool utility functions which are
 *      needed for use with the NetXDuo implementation.
 */

#pragma once

#include <nx_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Indicates transmit/receive direction for the packet buffer pool
 */
typedef enum
{
    NETXDUO_TX_POOL,           /**< Transmit direction */
    NETXDUO_RX_POOL            /**< Receive direction  */
} NetXDuo_PoolDir_t;


/** Register the packet buffer pools
 *
 *  Register the buffer pools to be used for packet allocation with NetXDuo.
 *  A pair of pools, one for RX buffers and one for TX buffers are passed
 *  in for use..
 *
 *  @param tx_packet_pool   Pointer to the initialized NetXDuo TX packet buffer pool
 *  @param rx_packet_pool   Pointer to the initialized NetXDuo RX packet buffer pool
 */
void netxduo_register_packet_pools(NX_PACKET_POOL * tx_packet_pool, NX_PACKET_POOL * rx_packet_pool);

/**
 * This function returns a packet buffer pool for the given packet direction.
 *
 * @param direction    Indicates transmit/receive direction of the packet pool.
 *
 * @return Pointer to the packet pool or NULL
 */
NX_PACKET_POOL * netxduo_get_packet_pool(NetXDuo_PoolDir_t direction);


#ifdef __cplusplus
} /* end extern "C" */
#endif
