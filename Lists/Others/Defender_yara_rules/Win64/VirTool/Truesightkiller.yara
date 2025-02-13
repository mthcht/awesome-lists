rule VirTool_Win64_Truesightkiller_A_2147911865_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Truesightkiller.A"
        threat_id = "2147911865"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Truesightkiller"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 4c 24 60 41 b9 ff 01 0f 00 48 89 4c 24 58 4c 8b c6 48 89 4c 24 50 48 8b d6 48 89 4c 24 48 48 89 4c 24 40 48 89 44 24 38 89 4c 24 30 48 8b cf c7 44 24 28 03 00 00 00 c7 44 24 20 01 00 00 00 ff ?? ?? ?? ?? ?? 48 8b d8 48 85 c0 ?? ?? 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {45 33 c9 4c 89 7c 24 30 c7 44 24 28 80 00 00 00 ?? ?? ?? ?? ?? ?? ?? 45 33 c0 c7 44 24 20 03 00 00 00 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 8b f0 48 83 f8 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 44 e0 22 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\\\.\\" ascii //weight: 1
        $x_1_5 = {2e 73 79 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

