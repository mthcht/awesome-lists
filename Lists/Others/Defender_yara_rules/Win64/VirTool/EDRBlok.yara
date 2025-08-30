rule VirTool_Win64_EDRBlok_A_2147950827_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/EDRBlok.A"
        threat_id = "2147950827"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "EDRBlok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 6c 24 68 bd 01 00 00 00 48 89 7c 24 38 ?? ?? ?? ?? ?? 89 7c 24 30 8b f7 ?? ?? ?? ?? 8d ?? ?? ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 4c 24 38 ?? ?? ?? ?? ?? 45 33 c9 48 89 44 24 20 45 33 c0 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 0e ff ?? ?? ?? ?? ?? 48 8b 0e 0f b6 10 ff ca ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

