rule VirTool_Win64_Komrat_A_2147832712_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Komrat.A!MTB"
        threat_id = "2147832712"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Komrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 8c 24 bc 00 00 00 68 cb 76 80 3b e8 ?? ?? ?? ?? 0f b6 0d 58 27 17 10 51 8b c8 e8 ?? ?? ?? ?? 8b 8c 24 bc 00 00 00 68 05 e0 3b 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 10 51 8b 55 0c 52 68 ff ff 00 00 6a 00 8b 45 08 50 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {52 8b 45 10 50 8b 4d 0c 51 8b 55 fc 52 8b 45 08 50 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

