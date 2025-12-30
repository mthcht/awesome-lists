rule VirTool_Win64_Shelesz_A_2147957266_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shelesz.A"
        threat_id = "2147957266"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 45 e7 8b 55 e7 83 c2 7d 33 54 85 f3 48 63 45 e7 89 54 85 f3 8b 45 e7 03 c7 89 45 e7 8b 45 e7 3b c7 ?? ?? 44 8b 4d fb 44 8b 45 f3 ba}  //weight: 1, accuracy: Low
        $x_1_2 = {48 63 45 e7 8b 55 e7 83 c2 7c 33 54 85 fb 48 63 45 e7 89 54 85 fb 8b 45 e7 03 c7 89 45 e7 8b 45 e7 3b c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Shelesz_A_2147957266_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shelesz.A"
        threat_id = "2147957266"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 81 ec e8 00 00 00 48 89 84 24 f8 00 00 00 48 89 9c 24 00 01 00 00 ?? ba 01 00 00 00 f0 0f c1 50 38 ff c2 85 d2 ?? ?? 48 83 c0 34 31 db 31 c9 e8 ?? ?? ?? ?? 48 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 48 81 ec b8 00 00 00 66 44 0f d6 bc 24 b0 00 00 00 48 89 84 24 c8 00 00 00 48 89 9c 24 d0 00 00 00 c6 44 24 3f 00 44 0f 11 7c 24 40 84 00 48 83 c0 28 48 89 44 24 58 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

