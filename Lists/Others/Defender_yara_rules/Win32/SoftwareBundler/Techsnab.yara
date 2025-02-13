rule SoftwareBundler_Win32_Techsnab_222310_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Techsnab"
        threat_id = "222310"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Techsnab"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "id=%s&hwaddr=%s&&user_os=%s&hdd_&status" ascii //weight: 1
        $x_2_2 = "channel=%sserial=%s&win_uu/f /im winupd.ex" ascii //weight: 2
        $x_1_3 = "%02X-%02X-%02X-%02X-%02X-%02X" ascii //weight: 1
        $x_2_4 = "&versie /fi \"PID ne %l&version=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule SoftwareBundler_Win32_Techsnab_222310_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Techsnab"
        threat_id = "222310"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Techsnab"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "v=%s&nuuid=%s" ascii //weight: 1
        $x_1_2 = {73 26 76 3d ?? ?? ?? ?? ?? ?? 25 73 26 6e ?? ?? ?? ?? ?? ?? 75 75 69 64 ?? ?? ?? ?? ?? ?? 3d 25 73 26 ?? ?? ?? ?? ?? ?? 75 73 65 72}  //weight: 1, accuracy: Low
        $x_2_3 = "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x" ascii //weight: 2
        $x_2_4 = "PROCESSOR_IDENTIFIER" ascii //weight: 2
        $x_1_5 = {43 6c 69 63 6b 20 6e 65 78 74 20 74 6f 20 73 74 61 72 74 20 64 6f 77 6e 6c 6f 61 64 21 00}  //weight: 1, accuracy: High
        $x_1_6 = {6e 6f 74 31 32 00}  //weight: 1, accuracy: High
        $x_1_7 = {6e 6f 74 45 6e 63 00}  //weight: 1, accuracy: High
        $x_1_8 = {02 74 0a b8 02 00 00 00 e9 ?? ?? ?? ?? b9 04 00 00 00 c1 e1 00 8b 55 ?? 8b 04 0a 50 e8 ?? ?? ?? ?? 83 c4 04 89 45 ?? 83 7d ?? 00 75 08}  //weight: 1, accuracy: Low
        $x_1_9 = {02 74 08 6a 02 58 e9 ?? ?? ?? ?? 6a 04 58 c1 e0 00 8b (4d ??|8d ?? ??) ff 34 01}  //weight: 1, accuracy: Low
        $x_1_10 = {02 74 08 6a 02 58 e9 ?? ?? ?? ?? 8b 45 ?? ff 70 04 e8 ?? ?? ?? ?? 59 89 45 ?? 83 7d ?? 00 75 08}  //weight: 1, accuracy: Low
        $x_1_11 = {6a 04 58 c1 e0 00 8b 8d ?? ?? ff ff 8b 04 01 89 85 ?? ?? ff ff 83 bd ?? ?? ff ff 02 74 08 6a 02 58 e9}  //weight: 1, accuracy: Low
        $x_1_12 = {02 74 08 6a 02 58 e9 ?? ?? ?? ?? 6a 04 58 c1 e0 00 8b 8d ?? ?? ff ff 8b 04 01}  //weight: 1, accuracy: Low
        $x_1_13 = {02 74 08 6a 02 58 e9 ?? ?? ?? ?? ff b5 ?? ?? ff ff e8 ?? ?? ?? ?? 59 89 85 ?? ?? ff ff (ff b5|e8 ?? ?? ?? ?? 83)}  //weight: 1, accuracy: Low
        $x_1_14 = {02 74 08 6a 02 58 e9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 f8 01 75 08 33 c0 40 e9}  //weight: 1, accuracy: Low
        $x_1_15 = {02 74 08 6a 02 58 e9 ?? ?? ?? ?? c7 85 ?? ?? ff ff 01 00 00 00 83 bd ?? ?? ff ff 02 74 08 6a 02 58 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

