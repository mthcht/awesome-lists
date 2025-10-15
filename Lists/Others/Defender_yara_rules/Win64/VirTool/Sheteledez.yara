rule VirTool_Win64_Sheteledez_A_2147955141_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Sheteledez.A"
        threat_id = "2147955141"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Sheteledez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 53 48 81 ec ?? ?? 00 00 48 ?? ?? ?? ?? ?? ?? 48 33 c4 48 89 84 24 00 02 00 00 85 d2 ?? ?? ?? ?? ?? ?? 83 fa 01 ?? ?? ?? ?? ?? ?? 33 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 5c 24 08 57 48 81 ec ?? ?? 00 00 48 ?? ?? ?? ?? ?? ?? 48 33 c4 48 89 84 24 c0 01 00 00 48 8b fa ?? ?? ?? ?? ?? ?? 8b d8 ?? ?? ?? ?? ?? ?? 44 8b cb 48 89 7c 24 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

