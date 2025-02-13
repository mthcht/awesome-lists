rule TrojanSpy_Win32_Aibatook_A_2147683595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Aibatook.A"
        threat_id = "2147683595"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Aibatook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 69 6b 6f 74 6f 62 61 [0-16] 6c 6f 67 69 6e 50 61 73 73 77 6f 72 64}  //weight: 1, accuracy: Low
        $x_2_2 = {3f 43 61 72 64 4e 75 6d 3d [0-96] 26 4c 6f 67 69 6e 50 61 73 73 3d [0-16] 26 50 61 79 50 61 73 73 3d}  //weight: 2, accuracy: Low
        $x_1_3 = {3f 4d 41 43 3d [0-16] 26 56 45 52 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Aibatook_B_2147683896_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Aibatook.B"
        threat_id = "2147683896"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Aibatook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "A599D752F6CC94D6BA9A8D4AA98FCBCE" ascii //weight: 10
        $x_3_2 = "aikotoba" ascii //weight: 3
        $x_1_3 = "A682C80CAF8CD68EAA88D75AE282C8D1" ascii //weight: 1
        $x_1_4 = "BB82D30CAF8CD68EAA88D70CAD90CB" ascii //weight: 1
        $x_1_5 = "BB82D50CAF8CD68EAA88D75AE282C8D1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Aibatook_C_2147688360_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Aibatook.C"
        threat_id = "2147688360"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Aibatook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 38 43 39 44 44 33 36 36 41 44 39 37 44 41 00}  //weight: 1, accuracy: High
        $x_1_2 = "9E82C556BB82C9C491A0CA41BE8CC8CEAB99FF75A58DDFCEBA9EFF61B991C9C4A" ascii //weight: 1
        $x_1_3 = {43 61 72 64 4e 75 6d 00 45 78 70 4d 00 00 00 00 45 78 70 59}  //weight: 1, accuracy: High
        $x_1_4 = {00 3f 4d 41 43 3d 00 [0-16] 26 56 45 52 3d 00}  //weight: 1, accuracy: Low
        $x_1_5 = {61 69 6b 6f 74 6f 62 61 [0-16] 6c 6f 67 69 6e 50 61 73 73 77 6f 72 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

