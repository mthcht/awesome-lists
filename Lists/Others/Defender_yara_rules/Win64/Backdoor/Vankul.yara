rule Backdoor_Win64_Vankul_ZA_2147837245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Vankul.ZA"
        threat_id = "2147837245"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Vankul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vulkan-1.dll.pdb" ascii //weight: 1
        $x_1_2 = "VK_LOADER_DEBUG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Vankul_A_2147839437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Vankul.A"
        threat_id = "2147839437"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Vankul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 44 8b d3 41 be bf e5 f1 78 48 8b 50 18 48 83 c2 10 48 8b 0a}  //weight: 1, accuracy: High
        $x_1_2 = {41 33 c0 44 69 c0 ?? ?? ?? ?? 41 8b c0 c1 e8 0f 44 33 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {41 be 0f 66 02 00 4c 8d 7f 04 4c 89 75 58 41 b9 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8a 44 05 48 30 02 49 03 d4 4d 2b f4 75}  //weight: 1, accuracy: High
        $x_1_5 = {ff d6 48 8d 87 44 6d 00 00 48 8d 4d 48 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

