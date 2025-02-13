rule VirTool_Win64_Hepenshellz_A_2147844675_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Hepenshellz.A!MTB"
        threat_id = "2147844675"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Hepenshellz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 45 33 c9 4c 8b 45 48 48 8d ?? ?? ?? ?? ?? 48 8b 8d a8 00 00 00 ff 15 ?? ?? ?? ?? 48 89 85 e8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 85 04 01 00 00 00 00 00 00 48 8d ?? ?? ?? ?? ?? 48 8b 8d e8 00 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {44 8b 85 04 01 00 00 48 8b 95 a8 01 00 00 48 8b 8d e8 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8b d0 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f b6 00 83 f0 7e 48 63 8d 24 02 00 00 48 8b 95 08 02 00 00 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

