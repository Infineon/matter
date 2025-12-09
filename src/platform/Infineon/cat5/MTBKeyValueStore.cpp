/*
 *
 *    Copyright (c) 2021 Project CHIP Authors
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
 *          Implementation of a key-value store using mtb_kvstore lib
 *
 */

#include "MTBKeyValueStore.h"
#include "mtb_kvstore_cat5.h"
#include "cybsp.h"
#include "cyhal.h"

cy_rslt_t mtb_key_value_store_init(mtb_kvstore_t * kvstore_obj)
{
    // Initialize the kv-store library
    return mtb_kvstore_init(kvstore_obj);
}

cy_rslt_t bd_read(mtb_kvstore_t * kvstore_obj, uint16_t key)
{
    uint32_t size;
    return mtb_kvstore_read_numeric_key(kvstore_obj, key, NULL, &size);
}

cy_rslt_t bd_program(mtb_kvstore_t * kvstore_obj, uint16_t key)
{
    bool overwrite_key = true;
    return mtb_kvstore_write_numeric_key(kvstore_obj, key, NULL, 0, overwrite_key);
}

cy_rslt_t bd_erase(mtb_kvstore_t * kvstore_obj)
{
    return mtb_kvstore_reset(kvstore_obj);
}
