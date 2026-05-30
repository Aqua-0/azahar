// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include "core/file_sys/garc_patch.h"

#include <algorithm>
#include <limits>
#include <utility>

#include "common/alignment.h"

namespace FileSys::GarcPatch {
namespace {

struct GarcHeaderFull {
    u16 version{};
    u32 section_size{};
    u32 data_offset{};
    u32 data_largest{};
    u32 data_largest_padded{};
    u32 padding_size{};
};

struct DataInfo {
    u32 start_offset{};
    u32 end_offset{};
    u32 unpadded_len{};
};

struct FatbEntry {
    u32 lang_bits{};
    std::vector<std::pair<u8, DataInfo>> infos;
};

void SetError(std::string* error, std::string message) {
    if (error) {
        *error = std::move(message);
    }
}

bool ReadU16Le(const std::vector<u8>& bytes, std::size_t offset, u16& out) {
    if (offset > bytes.size() || bytes.size() - offset < 2) {
        return false;
    }
    out = static_cast<u16>(static_cast<u16>(bytes[offset]) |
                           (static_cast<u16>(bytes[offset + 1]) << 8));
    return true;
}

bool ReadU32Le(const std::vector<u8>& bytes, std::size_t offset, u32& out) {
    if (offset > bytes.size() || bytes.size() - offset < 4) {
        return false;
    }
    out = static_cast<u32>(bytes[offset]) | (static_cast<u32>(bytes[offset + 1]) << 8) |
          (static_cast<u32>(bytes[offset + 2]) << 16) |
          (static_cast<u32>(bytes[offset + 3]) << 24);
    return true;
}

void WriteU16Le(std::vector<u8>& out, u16 value) {
    out.push_back(static_cast<u8>(value & 0xFF));
    out.push_back(static_cast<u8>((value >> 8) & 0xFF));
}

void WriteU32Le(std::vector<u8>& out, u32 value) {
    out.push_back(static_cast<u8>(value & 0xFF));
    out.push_back(static_cast<u8>((value >> 8) & 0xFF));
    out.push_back(static_cast<u8>((value >> 16) & 0xFF));
    out.push_back(static_cast<u8>((value >> 24) & 0xFF));
}

bool AddU32(u32 a, u32 b, u32& out) {
    if (a > std::numeric_limits<u32>::max() - b) {
        return false;
    }
    out = a + b;
    return true;
}

bool ToU32(std::size_t value, u32& out) {
    if (value > std::numeric_limits<u32>::max()) {
        return false;
    }
    out = static_cast<u32>(value);
    return true;
}

bool CheckMagic(const std::vector<u8>& bytes, std::size_t offset, const char* magic) {
    return offset <= bytes.size() && bytes.size() - offset >= 4 &&
           std::equal(magic, magic + 4, bytes.begin() + offset);
}

Loader::ResultStatus ReadHeaderFull(const std::vector<u8>& bytes, GarcHeaderFull& hdr,
                                    std::string* error) {
    if (bytes.size() < 0x1C) {
        SetError(error, "GARC too small");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }
    if (!CheckMagic(bytes, 0, "CRAG")) {
        SetError(error, "Bad GARC magic (expected CRAG)");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }

    u16 bom{};
    u32 block_count{};
    if (!ReadU32Le(bytes, 4, hdr.section_size) || !ReadU16Le(bytes, 8, bom) ||
        !ReadU16Le(bytes, 0x0A, hdr.version) || !ReadU32Le(bytes, 0x0C, block_count) ||
        !ReadU32Le(bytes, 0x10, hdr.data_offset)) {
        SetError(error, "Unexpected EOF while reading GARC header");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }

    if (bom != 0xFEFF) {
        SetError(error, "Big-endian GARC not supported");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }
    if (block_count != 4) {
        SetError(error, "Unsupported GARC block count");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }

    if (hdr.version == 0x0400) {
        if (!ReadU32Le(bytes, 0x18, hdr.data_largest)) {
            SetError(error, "Unexpected EOF while reading GARC v4 header");
            return Loader::ResultStatus::ErrorInvalidFormat;
        }
        hdr.data_largest_padded = hdr.data_largest;
        hdr.padding_size = 4;
    } else if (hdr.version == 0x0600) {
        if (bytes.size() < 0x24 || !ReadU32Le(bytes, 0x18, hdr.data_largest_padded) ||
            !ReadU32Le(bytes, 0x1C, hdr.data_largest) ||
            !ReadU32Le(bytes, 0x20, hdr.padding_size)) {
            SetError(error, "Unexpected EOF while reading GARC v6 header");
            return Loader::ResultStatus::ErrorInvalidFormat;
        }
    } else {
        SetError(error, "Unsupported GARC version");
        return Loader::ResultStatus::ErrorNotImplemented;
    }

    if (hdr.section_size > bytes.size()) {
        SetError(error, "GARC header section extends past file end");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }
    return Loader::ResultStatus::Success;
}

Loader::ResultStatus ParseFato(const std::vector<u8>& bytes, std::size_t fato_start, u32& fato_size,
                               std::vector<u32>& fatb_offsets, std::string* error) {
    if (fato_start > bytes.size() || bytes.size() - fato_start < 12) {
        SetError(error, "GARC missing FATO header");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }
    if (!CheckMagic(bytes, fato_start, "OTAF")) {
        SetError(error, "Bad FATO magic");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }

    u16 entry_count{};
    if (!ReadU32Le(bytes, fato_start + 4, fato_size) ||
        !ReadU16Le(bytes, fato_start + 8, entry_count)) {
        SetError(error, "Unexpected EOF while reading FATO header");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }
    if (fato_start + fato_size < fato_start || fato_start + fato_size > bytes.size()) {
        SetError(error, "FATO block extends past file end");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }

    const std::size_t table_start = fato_start + 12;
    const std::size_t table_len = static_cast<std::size_t>(entry_count) * 4;
    if (table_start > bytes.size() || bytes.size() - table_start < table_len) {
        SetError(error, "GARC FATO offsets out of range");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }

    fatb_offsets.clear();
    fatb_offsets.reserve(entry_count);
    for (u16 i = 0; i < entry_count; ++i) {
        u32 offset{};
        ReadU32Le(bytes, table_start + static_cast<std::size_t>(i) * 4, offset);
        fatb_offsets.push_back(offset);
    }
    return Loader::ResultStatus::Success;
}

Loader::ResultStatus ParseFatbEntries(const std::vector<u8>& bytes, std::size_t fatb_start,
                                      u32 fatb_size, const std::vector<u32>& fatb_offsets,
                                      std::vector<FatbEntry>& out, std::string* error) {
    if (fatb_start > bytes.size() || bytes.size() - fatb_start < 12) {
        SetError(error, "GARC missing FATB header");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }
    if (!CheckMagic(bytes, fatb_start, "BTAF")) {
        SetError(error, "Bad FATB magic");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }
    if (fatb_start + fatb_size < fatb_start || fatb_start + fatb_size > bytes.size()) {
        SetError(error, "FATB block extends past file end");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }

    const std::size_t entries_base = fatb_start + 12;
    const std::size_t entries_end = fatb_start + fatb_size;
    out.clear();
    out.reserve(fatb_offsets.size());

    for (const u32 fatb_offset : fatb_offsets) {
        const std::size_t entry_pos = entries_base + fatb_offset;
        if (entry_pos < entries_base || entry_pos > entries_end || entries_end - entry_pos < 4) {
            SetError(error, "FATB entry offset out of range");
            return Loader::ResultStatus::ErrorInvalidFormat;
        }

        FatbEntry entry;
        if (!ReadU32Le(bytes, entry_pos, entry.lang_bits)) {
            SetError(error, "Unexpected EOF while reading FATB entry");
            return Loader::ResultStatus::ErrorInvalidFormat;
        }

        std::size_t cursor = entry_pos + 4;
        for (u8 bit = 0; bit < 32; ++bit) {
            if (((entry.lang_bits >> bit) & 1) == 0) {
                continue;
            }
            if (cursor > entries_end || entries_end - cursor < 12) {
                SetError(error, "Unexpected EOF while reading FATB data info");
                return Loader::ResultStatus::ErrorInvalidFormat;
            }

            DataInfo info;
            ReadU32Le(bytes, cursor, info.start_offset);
            ReadU32Le(bytes, cursor + 4, info.end_offset);
            ReadU32Le(bytes, cursor + 8, info.unpadded_len);
            entry.infos.emplace_back(bit, info);
            cursor += 12;
        }
        out.push_back(std::move(entry));
    }

    return Loader::ResultStatus::Success;
}

Loader::ResultStatus CopyEntryData(const std::vector<u8>& garc, u32 data_offset, DataInfo info,
                                   std::vector<u8>& out, std::string* error) {
    u32 start{};
    if (!AddU32(data_offset, info.start_offset, start)) {
        SetError(error, "Overflow computing GARC data slice");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }
    const std::size_t start_size = start;
    if (start_size > garc.size() || garc.size() - start_size < info.unpadded_len) {
        SetError(error, "GARC data slice out of range");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }
    out.assign(garc.begin() + start_size, garc.begin() + start_size + info.unpadded_len);
    return Loader::ResultStatus::Success;
}

} // namespace

Loader::ResultStatus RepackDefaultLanguageMembers(const std::vector<u8>& garc,
                                                   const MemberOverrideMap& member_overrides,
                                                   std::vector<u8>& out,
                                                   std::string* error) {
    out.clear();

    GarcHeaderFull hdr;
    if (const auto ret = ReadHeaderFull(garc, hdr, error); ret != Loader::ResultStatus::Success) {
        return ret;
    }

    const std::size_t fato_start = hdr.section_size;
    u32 fato_old_size{};
    std::vector<u32> fatb_offsets;
    if (const auto ret = ParseFato(garc, fato_start, fato_old_size, fatb_offsets, error);
        ret != Loader::ResultStatus::Success) {
        return ret;
    }

    const std::size_t fatb_start = fato_start + fato_old_size;
    u32 fatb_old_size{};
    if (!ReadU32Le(garc, fatb_start + 4, fatb_old_size)) {
        SetError(error, "Unexpected EOF while reading FATB size");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }

    std::vector<FatbEntry> fatb_entries;
    if (const auto ret =
            ParseFatbEntries(garc, fatb_start, fatb_old_size, fatb_offsets, fatb_entries, error);
        ret != Loader::ResultStatus::Success) {
        return ret;
    }

    for (const auto& override_entry : member_overrides) {
        if (override_entry.first >= fatb_entries.size()) {
            SetError(error, "GARC member override id out of range");
            return Loader::ResultStatus::ErrorInvalidFormat;
        }
    }

    if (hdr.padding_size == 0 || (hdr.padding_size & (hdr.padding_size - 1)) != 0) {
        SetError(error, "Unsupported GARC padding size");
        return Loader::ResultStatus::ErrorInvalidFormat;
    }

    std::vector<FatbEntry> new_entries;
    std::vector<u8> data;
    u32 max_unpadded = 0;
    u32 max_padded = 0;
    new_entries.reserve(fatb_entries.size());

    for (std::size_t entry_idx = 0; entry_idx < fatb_entries.size(); ++entry_idx) {
        const auto& entry = fatb_entries[entry_idx];
        FatbEntry new_entry;
        new_entry.lang_bits = entry.lang_bits;
        new_entry.infos.reserve(entry.infos.size());

        for (const auto& [bit, old_info] : entry.infos) {
            std::vector<u8> payload;
            const auto override_it = member_overrides.find(static_cast<u32>(entry_idx));
            if (bit == 0 && override_it != member_overrides.end()) {
                payload = override_it->second;
            } else if (const auto ret =
                           CopyEntryData(garc, hdr.data_offset, old_info, payload, error);
                       ret != Loader::ResultStatus::Success) {
                return ret;
            }

            const std::size_t start_offset = data.size();
            data.insert(data.end(), payload.begin(), payload.end());
            const auto padded_len =
                Common::AlignUp(static_cast<u64>(payload.size()), hdr.padding_size);
            if (padded_len > data.size() - start_offset) {
                data.resize(start_offset + padded_len, 0xFF);
            }
            const std::size_t end_offset = data.size();

            DataInfo new_info;
            if (!ToU32(start_offset, new_info.start_offset) ||
                !ToU32(end_offset, new_info.end_offset) ||
                !ToU32(payload.size(), new_info.unpadded_len)) {
                SetError(error, "GARC entry too large");
                return Loader::ResultStatus::ErrorMemoryAllocationFailed;
            }

            u32 padded_u32{};
            if (!ToU32(padded_len, padded_u32)) {
                SetError(error, "GARC entry too large");
                return Loader::ResultStatus::ErrorMemoryAllocationFailed;
            }
            max_unpadded = std::max(max_unpadded, new_info.unpadded_len);
            max_padded = std::max(max_padded, padded_u32);
            new_entry.infos.emplace_back(bit, new_info);
        }

        new_entries.push_back(std::move(new_entry));
    }

    if (new_entries.size() > std::numeric_limits<u16>::max()) {
        SetError(error, "GARC entry count too large");
        return Loader::ResultStatus::ErrorMemoryAllocationFailed;
    }

    u32 entry_count_u32{};
    if (!ToU32(new_entries.size(), entry_count_u32)) {
        SetError(error, "GARC entry count too large");
        return Loader::ResultStatus::ErrorMemoryAllocationFailed;
    }

    u32 fato_size{};
    if (!AddU32(12, entry_count_u32 * 4, fato_size)) {
        SetError(error, "Overflow computing FATO size");
        return Loader::ResultStatus::ErrorMemoryAllocationFailed;
    }

    std::vector<u32> fatb_entry_offsets;
    fatb_entry_offsets.reserve(new_entries.size());
    u32 fatb_payload_len = 0;
    u32 total_subentries = 0;
    for (const auto& entry : new_entries) {
        fatb_entry_offsets.push_back(fatb_payload_len);

        u32 info_count{};
        if (!ToU32(entry.infos.size(), info_count) ||
            !AddU32(total_subentries, info_count, total_subentries)) {
            SetError(error, "GARC FATB entry count too large");
            return Loader::ResultStatus::ErrorMemoryAllocationFailed;
        }

        u32 entry_size{};
        if (!AddU32(4, info_count * 12, entry_size) ||
            !AddU32(fatb_payload_len, entry_size, fatb_payload_len)) {
            SetError(error, "Overflow computing FATB size");
            return Loader::ResultStatus::ErrorMemoryAllocationFailed;
        }
    }

    u32 fatb_size{};
    if (!AddU32(12, fatb_payload_len, fatb_size)) {
        SetError(error, "Overflow computing FATB size");
        return Loader::ResultStatus::ErrorMemoryAllocationFailed;
    }

    u32 data_len_u32{};
    if (!ToU32(data.size(), data_len_u32)) {
        SetError(error, "GARC data too large");
        return Loader::ResultStatus::ErrorMemoryAllocationFailed;
    }

    u32 data_offset_new{};
    u32 arc_size_new{};
    if (!AddU32(hdr.section_size, fato_size, data_offset_new) ||
        !AddU32(data_offset_new, fatb_size, data_offset_new) ||
        !AddU32(data_offset_new, 12, data_offset_new) ||
        !AddU32(data_offset_new, data_len_u32, arc_size_new)) {
        SetError(error, "Overflow computing GARC output size");
        return Loader::ResultStatus::ErrorMemoryAllocationFailed;
    }

    const u32 data_largest = std::max(hdr.data_largest, max_unpadded);
    const u32 data_largest_padded = std::max(hdr.data_largest_padded, max_padded);

    out.reserve(arc_size_new);
    out.insert(out.end(), {'C', 'R', 'A', 'G'});
    WriteU32Le(out, hdr.section_size);
    WriteU16Le(out, 0xFEFF);
    WriteU16Le(out, hdr.version);
    WriteU32Le(out, 4);
    WriteU32Le(out, data_offset_new);
    WriteU32Le(out, arc_size_new);
    if (hdr.version == 0x0400) {
        WriteU32Le(out, data_largest);
    } else {
        WriteU32Le(out, data_largest_padded);
        WriteU32Le(out, data_largest);
        WriteU32Le(out, hdr.padding_size);
    }

    if (out.size() < hdr.section_size) {
        out.resize(hdr.section_size, 0);
    }
    if (out.size() != hdr.section_size) {
        SetError(error, "Internal GARC header length mismatch");
        return Loader::ResultStatus::Error;
    }

    out.insert(out.end(), {'O', 'T', 'A', 'F'});
    WriteU32Le(out, fato_size);
    WriteU16Le(out, static_cast<u16>(new_entries.size()));
    WriteU16Le(out, 0xFFFF);
    for (const u32 offset : fatb_entry_offsets) {
        WriteU32Le(out, offset);
    }

    out.insert(out.end(), {'B', 'T', 'A', 'F'});
    WriteU32Le(out, fatb_size);
    WriteU32Le(out, total_subentries);
    for (const auto& entry : new_entries) {
        WriteU32Le(out, entry.lang_bits);
        for (const auto& info_entry : entry.infos) {
            WriteU32Le(out, info_entry.second.start_offset);
            WriteU32Le(out, info_entry.second.end_offset);
            WriteU32Le(out, info_entry.second.unpadded_len);
        }
    }

    out.insert(out.end(), {'B', 'M', 'I', 'F'});
    WriteU32Le(out, 12);
    WriteU32Le(out, data_len_u32);

    if (out.size() != data_offset_new) {
        SetError(error, "Internal GARC data offset mismatch");
        return Loader::ResultStatus::Error;
    }

    out.insert(out.end(), data.begin(), data.end());
    return Loader::ResultStatus::Success;
}

} // namespace FileSys::GarcPatch
