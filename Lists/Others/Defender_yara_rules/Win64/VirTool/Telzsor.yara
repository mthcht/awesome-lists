rule VirTool_Win64_Telzsor_A_2147841302_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Telzsor.A!MTB"
        threat_id = "2147841302"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Telzsor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 00 48 89 45 68 48 63 45 44 48 8b 4d 68 48 81 c1 10 02 00 00 48 8b d0 e8 ?? ?? ?? ?? 48 8b 00 48 89 85 88 00 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 85 88 00 00 00 48 83 c0 10 48 8b 4d 08 48 89 41 30 eb 5b}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 85 c8 00 00 00 48 89 44 24 20 41 b9 00 20 00 00 4c 8b 85 c8 00 00 00 ba 08 20 00 80 48 8b 4d 48 ff}  //weight: 1, accuracy: High
        $x_1_4 = {48 89 45 28 48 8b 95 48 01 00 00 48 8d 0d c8 46 13 00 e8 ?? ?? ?? ?? 48 8b 00 48 89 45 48 48 8b 85 50 01 00 00 48 89 85 18 01 00 00 48 83 bd 18 01 00 00 00 74 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

