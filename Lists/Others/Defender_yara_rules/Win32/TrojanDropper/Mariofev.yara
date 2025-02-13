rule TrojanDropper_Win32_Mariofev_A_2147607909_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Mariofev.A"
        threat_id = "2147607909"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Mariofev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {00 20 70 20 49 20 6e 20 69 20 74 20 5f 20 44 20 6c 20 6c 20 73 00}  //weight: 8, accuracy: High
        $x_2_2 = "dllcache\\user32.dll" ascii //weight: 2
        $x_2_3 = {57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 [0-16] 41 70 70 49 6e 69 74 5f 44 6c 6c 73 00}  //weight: 2, accuracy: Low
        $x_1_4 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_5 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_6 = "FindResourceA" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Mariofev_B_2147617523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Mariofev.B"
        threat_id = "2147617523"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Mariofev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {76 1e 8d 7c 24 10 4f 8a 14 0f 8b 74 24 14 02 d0 30 14 30 83 f9 04 75 02 33 c9 40 41 3b c5 72 e7}  //weight: 3, accuracy: High
        $x_2_2 = {75 26 80 be ?? ?? ?? ?? c0 75 1d 80 be ?? ?? ?? ?? 40 75 14 88 96 02 00 b2 90}  //weight: 2, accuracy: Low
        $x_1_3 = {25 00 73 00 5c 00 74 00 72 00 61 00 73 00 68 00 25 00 58 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 63 74 66 6d 6f 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Mariofev_I_2147637993_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Mariofev.I"
        threat_id = "2147637993"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Mariofev"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 45 f0 e0 00 00 e0 8d 0c ca}  //weight: 2, accuracy: High
        $x_2_2 = {c7 44 24 44 e0 00 00 e0 8d 04 c1}  //weight: 2, accuracy: High
        $x_2_3 = {6a 05 50 8d 4d d4 e8 ?? ?? ?? ?? 80 7d c0 e9 75 1e}  //weight: 2, accuracy: Low
        $x_2_4 = {6a 05 50 8d 4c 24 28 e8 ?? ?? ?? ?? 80 7c 24 30 e9 75 2c}  //weight: 2, accuracy: Low
        $x_5_5 = "&DisableSfc=%d-%d" ascii //weight: 5
        $x_5_6 = "&PatchFile=%d-%d" ascii //weight: 5
        $x_1_7 = "dllcache\\ole32.dll" ascii //weight: 1
        $x_1_8 = "DEPACKEND" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

