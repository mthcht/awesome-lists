rule VirTool_Win64_Rogue_A_2147780244_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Rogue.A"
        threat_id = "2147780244"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rogue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 53 48 83 ec ?? 48 8b 05 63 26 02 00 48 33 c4 48 89 44 24 48 48 8b d9 4c 8d ?? ?? ?? 33 c9 ff 15 ?? ?? ?? ?? 85 c0 75 21 48 8d 0d 80 f1 01 00 e8 ?? ?? ?? ?? 33 c0 48 8b 4c 24 48 48 33 cc e8 ?? ?? ?? ?? 48 83 c4 50 5b c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 44 24 30 4c 8d ?? ?? ?? 48 89 44 24 3c 33 d2 33 c0 c7 44 24 38 01 00 00 00 48 89 44 24 28 48 8b cb c7 44 24 44 02 00 00 00 48 89 44 24 20 44 ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 75 21 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 48 8b 4c 24 48 48 33 cc e8 ?? ?? ?? ?? 48 83 c4 50 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

