rule VirTool_Win32_Avet_12_2147844470_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Avet.12!MTB"
        threat_id = "2147844470"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Avet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 2c 8b 8c 24 5c 28 00 00 89 4c 24 10 89 54 24 0c 8b 94 24 64 28 00 00 89 54 24 08 89 44 24 04 8b 84 24 68 28 00 00 89 04 24 8b 84 24 74 28 00 00 ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b 84 24 98 28 00 00 8b 84 84 34 28 00 00 8d 54 ?? ?? 8b 8c 24 98 28 00 00 c1 e1 0a 01 ca 89 14 24 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {89 44 24 08 c7 44 ?? ?? ?? ?? ?? ?? 89 14 24 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {81 e9 00 10 00 00 83 09 00 2d 00 10 00 00 3d 00 10 00 00 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Avet_14_2147844678_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Avet.14!MTB"
        threat_id = "2147844678"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Avet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 30 00 00 00 00 8b 45 0c 83 c0 10 8b 00 8d 54 ?? ?? 89 54 24 04 89 04 24 8b 84 24 84 28 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {81 e9 00 10 00 00 83 09 00 2d 00 10 00 00 3d 00 10 00 00 77}  //weight: 1, accuracy: High
        $x_1_3 = {8b 84 24 98 28 00 00 8b 84 84 34 28 00 00 8d ?? ?? ?? 8b 94 24 98 28 00 00 c1 e2 0a 01 ca 89 14 24 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

