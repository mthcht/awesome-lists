rule Trojan_Win64_jscramSteal_DA_2147973324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/jscramSteal.DA!MTB"
        threat_id = "2147973324"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "jscramSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows stdio in console mode does not support writing non-UTF-8 byte sequences" ascii //weight: 1
        $x_1_2 = "strings passed to WinAPI cannot contain NULs" ascii //weight: 1
        $x_1_3 = "cannot set file timestamp to 0xFFFF_FFFF_FFFF_FFFF" ascii //weight: 1
        $x_1_4 = "Unsupported reparse point type" ascii //weight: 1
        $x_1_5 = "path cannot be split to be inserted into archive" ascii //weight: 1
        $x_1_6 = "hard link listed for" ascii //weight: 1
        $x_1_7 = "symlink destination for" ascii //weight: 1
        $x_1_8 = "when getting length from sparse header" ascii //weight: 1
        $x_1_9 = "when getting offset from sparse header" ascii //weight: 1
        $x_1_10 = "more bytes listed in sparse file than u64 can hold" ascii //weight: 1
        $x_1_11 = "sparse file consumed more data than the header listed" ascii //weight: 1
        $x_1_12 = "mismatch in sparse file chunks and entry size in header" ascii //weight: 1
        $x_1_13 = "previous block in sparse file was not aligned to 512-byte boundary" ascii //weight: 1
        $x_1_14 = "archive header checksum mismatch" ascii //weight: 1
        $x_1_15 = "unexpected EOF during skip" ascii //weight: 1
        $x_1_16 = "failed to unpack" ascii //weight: 1
        $x_1_17 = "failed to write whole buffer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

