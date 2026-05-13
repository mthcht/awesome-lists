rule VirTool_Win64_Hijesz_A_2147969162_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Hijesz.A"
        threat_id = "2147969162"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Hijesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 53 08 41 b9 08 00 00 00 ?? ?? ?? ?? 48 8b cb e8 ?? ?? ?? ?? 66 c7 45 c0 ?? ?? 48 8b 53 08 41 b9 02 00 00 00 ?? ?? ?? ?? 48 8b cb e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 45 e0 4c 89 65 80 c7 44 24 28 40 00 00 00 c7 44 24 20 00 30 00 00 ?? ?? ?? ?? 45 33 c0 ?? ?? ?? ?? 48 8b cb ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

