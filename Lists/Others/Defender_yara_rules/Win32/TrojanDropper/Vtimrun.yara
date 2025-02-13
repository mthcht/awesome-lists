rule TrojanDropper_Win32_Vtimrun_B_2147625055_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vtimrun.B"
        threat_id = "2147625055"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vtimrun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 03 6a 10 58 57 8d 4d ?? 51 50 8d 45 ?? 50 ff 75 fc ff 15 ?? ?? 40 00 83 6d ?? 10 83 45 ?? 10 43 3b 1e 7c c7}  //weight: 2, accuracy: Low
        $x_2_2 = {3b c7 74 0c ff 75 fc ff 75 f4 ff d0 85 c0 75 06 53 e9 81 00 00 00 39 7d f0 74 15}  //weight: 2, accuracy: High
        $x_2_3 = {83 7d f4 02 75 14 83 7d e8 05 75 0e 33 c0 40 83 7d ec 00 74 07 39 45 ec 74 02 32 c0}  //weight: 2, accuracy: High
        $x_1_4 = "%s\\%d_res.tmp" ascii //weight: 1
        $x_1_5 = {5f 4d 69 73 73 69 6f 6e 42 72 69 65 66 69 6e 67 40 [0-7] 5f 49 6e 73 74 61 6c 6c 40}  //weight: 1, accuracy: Low
        $x_1_6 = {41 64 64 41 63 63 65 73 73 41 6c 6c 6f 77 65 64 41 63 65 45 78 [0-7] 5c 44 72 69 76 65 72 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Vtimrun_C_2147630826_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vtimrun.C"
        threat_id = "2147630826"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vtimrun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 00 50 e8 ?? ?? 00 00 8d 85 ?? ?? ff ff c6 ?? ?? 44 50 8d 85 ?? ?? ff ff 50 c6 ?? ?? 6c c6 ?? ?? 6c c6 ?? ?? 43 c6 ?? ?? 61 c6 ?? ?? 63 c6 ?? ?? 68 c6 ?? ?? 65 c6 ?? ?? 5c 88 ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {40 65 63 68 6f [0-5] 6f 66 66 0d 0a 3a 74 72 79 [0-7] 64 65 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

