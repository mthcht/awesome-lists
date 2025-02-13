rule VirTool_Win64_Herpaderping_2147781490_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Herpaderping"
        threat_id = "2147781490"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Herpaderping"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 48 89 bd 10 09 00 00 89 7c 24 40 48 89 7c 24 38 48 89 7c 24 30 4c 89 6c 24 28 c7 44 24 20 04 00 00 00 4c 8d ?? ?? 45 33 c0 ba ff ff 1f 00 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 48 89 bd 10 09 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 ad 40 09 00 00 4c 89 ad 28 09 00 00 48 89 5c 24 30 c7 44 24 28 00 00 00 01 c7 44 24 20 02 00 00 00 45 33 c9 45 33 c0 ba 1f 00 0f 00 48 8d ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 4c 89 ad 28 09 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 74 24 20 4c 8b cf 49 8b cf ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 48 8b 8d a8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 8b cf 49 c1 e9 20 48 89 74 24 28 89 7c 24 20 33 d2 44 8d ?? ?? 48 8b cd ff 15 ?? ?? ?? ?? 48 8b d8 4c 8b f0 48 ff c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

