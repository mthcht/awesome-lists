rule VirTool_Win64_Eumbra_A_2147757236_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Eumbra.A"
        threat_id = "2147757236"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Eumbra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 31 c2 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 f0 72 cd 48 8b 55 e8 48 8b 45 f8 48 01 d0 c6 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {70 61 79 6c 6f 61 64 3d [0-4] 2f 77 69 6e 64 6f 77 73 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 00 73 00 74 00 61 00 67 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 00 4f 00 53 00 54 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "Blocked: " ascii //weight: 1
        $x_1_6 = "WinHttpQueryDataAvailable" ascii //weight: 1
        $x_1_7 = "beacon.exe" ascii //weight: 1
        $x_1_8 = {c7 44 24 30 00 01 80 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 [0-32] 48 89 45 ?? 48 83 7d ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win64_Eumbra_A_2147757236_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Eumbra.A"
        threat_id = "2147757236"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Eumbra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 31 c2 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 f0 72 cd 48 8b 55 e8 48 8b 45 f8 48 01 d0 c6 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {2f 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 00 74 00 61 00 73 00 6b 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {50 00 4f 00 53 00 54 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "username=%s&domain=%s&machine=%s" ascii //weight: 1
        $x_1_6 = "Blocked: " ascii //weight: 1
        $x_1_7 = "WinHttpQueryDataAvailable" ascii //weight: 1
        $x_1_8 = "beacon.exe" ascii //weight: 1
        $x_1_9 = {c7 44 24 30 00 01 80 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 [0-32] 48 89 45 ?? 48 83 7d ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_10 = "{\"id\":\"%s\",\"opcode\":%d,\"data\":\"%s\"}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

