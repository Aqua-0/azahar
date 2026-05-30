// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <map>
#include <string>
#include <vector>

#include "common/common_types.h"
#include "core/loader/loader.h"

namespace FileSys::GarcPatch {

using MemberOverrideMap = std::map<u32, std::vector<u8>>;

Loader::ResultStatus RepackDefaultLanguageMembers(const std::vector<u8>& garc,
                                                   const MemberOverrideMap& member_overrides,
                                                   std::vector<u8>& out,
                                                   std::string* error = nullptr);

} // namespace FileSys::GarcPatch
