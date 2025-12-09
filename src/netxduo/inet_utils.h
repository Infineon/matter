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
 *      This header file defines some Inet utility functions which are
 *      not included in the NetXDuo distribution.
 */

#pragma once

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *inet_ntop4(const unsigned char *src, char *dst, size_t size);
const char *inet_ntop6(const unsigned char *src, char *dst, size_t size);

int inet_pton4(const char *src, unsigned char *dst);
int inet_pton6(const char *src, unsigned char *dst);


#ifdef __cplusplus
} /* end extern "C" */
#endif
