/* Copyright (C) 2015-2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 */

#ifndef __DETECT_DIAMETER_FLAGS_H__
#define __DETECT_DIAMETER_FLAGS_H__


#define DIAMETER_FLAG_R 0x80
#define DIAMETER_FLAG_P 0x40
#define DIAMETER_FLAG_E 0x20
#define DIAMETER_FLAG_T 0x10

typedef uint8_t DiameterFlagsData;

typedef struct DetectDiameterFlagsData_ {
    DiameterFlagsData flags;
} DetectDiameterFlagsData;

void DetectDiameterflagsRegister(void);

#endif /* __DETECT_DIAMETER_FLAGS_H__ */
