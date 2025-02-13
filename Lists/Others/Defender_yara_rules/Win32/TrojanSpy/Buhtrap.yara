rule TrojanSpy_Win32_Buhtrap_A_2147718114_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Buhtrap.A!dha"
        threat_id = "2147718114"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Buhtrap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 31 7e 8a 01 41 84 c0 75 f6}  //weight: 1, accuracy: High
        $x_1_2 = " %d / %d results" wide //weight: 1
        $x_1_3 = "=%d-%02d-%02d %02d:%02d:%02d" wide //weight: 1
        $x_1_4 = "ERROR: Open failed %s %d" wide //weight: 1
        $x_1_5 = "Max: %ls, Total: %s, Min: %d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Buhtrap_A_2147718860_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Buhtrap.A!bit"
        threat_id = "2147718860"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Buhtrap"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 8a 9c 35 ?? ?? ?? ff 99 f7 7d ?? 8a 04 3a 02 c3 02 f8 0f b6 cf 8a 84 0d ?? ?? ?? ff 88 84 35 ?? ?? ?? ff 46 88 9c 0d ?? ?? ?? ff 81 fe 00 01 00 00 7c cb 83 7d fc 00 7e 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {fe c3 88 5d ?? 0f b6 f3 02 94 35 ?? ?? ?? ff 88 55 ?? 8a 8c 35 ?? ?? ?? ff 0f b6 d2 8a 84 15 ?? ?? ?? ff 88 84 35 ?? ?? ?? ff 88 8c 15 ?? ?? ?? ff 8a 55 ?? 8a 5d ?? 0f b6 ca 0f b6 c3 8a 8c 0d ?? ?? ?? ff 02 8c 05 ?? ?? ?? ff 0f b6 c1 8b 4d f8 8a 84 05 ?? ?? ?? ff 30 04 0f 47 3b 7d fc 7c 9f}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 09 5a b9 ?? ?? ?? 00 e8 ?? ?? ?? 00 6a 06 5a b9 ?? ?? ?? 00 89 45 ?? e8 ?? ?? ?? 00 6a 09 5a b9 ?? ?? ?? 00 89 45 ?? e8 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_2_4 = {00 31 41 35 39 44 35 41 42 45 42 46 44 36 35 32 44 38 32 36 41 39 37 36 43 33 43 38 31 43 43 36 43 00}  //weight: 2, accuracy: High
        $x_1_5 = {00 00 52 00 65 00 74 00 75 00 72 00 6e 00 56 00 61 00 6c 00 75 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Buhtrap_B_2147741096_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Buhtrap.B"
        threat_id = "2147741096"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Buhtrap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"encryptedPassword\":\"" ascii //weight: 1
        $x_1_2 = "signons.sqlite" wide //weight: 1
        $x_1_3 = "outlook account manager passwords" wide //weight: 1
        $x_1_4 = "inetcomm server passwords" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

