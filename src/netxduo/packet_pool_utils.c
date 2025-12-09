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
 *      This header file provides some packet pool utility functions which are
 *      needed for use with the NetXDuo implementation.
 */

#include <nx_api.h>

#include <packet_pool_utils.h>

#ifdef __cplusplus
extern "C" {
#endif

static NX_PACKET_POOL * sTxPool;
static NX_PACKET_POOL * sRxPool;

void netxduo_register_packet_pools(NX_PACKET_POOL * tx_packet_pool, NX_PACKET_POOL * rx_packet_pool)
{
    sTxPool = tx_packet_pool;
    sRxPool = rx_packet_pool;
}


NX_PACKET_POOL * netxduo_get_packet_pool(NetXDuo_PoolDir_t direction)
{
    if (direction == NETXDUO_TX_POOL)
    {
        return sTxPool;
    }
    else if (direction == NETXDUO_RX_POOL)
    {
        return sRxPool;
    }

    return NULL;
}


#ifdef __cplusplus
} /* end extern "C" */
#endif
