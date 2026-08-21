rule VirTool_Win64_Dempecresz_A_2147976633_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dempecresz.A"
        threat_id = "2147976633"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dempecresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 d9 48 89 f2 e8 ?? ?? ?? ?? 48 89 c3 48 8b [0-18] e8 ?? ?? ?? ?? f6 85 f0 02 00 00 01 ?? ?? ?? ?? ?? ?? f6 85 e8 02 00 00 01}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 f1 4c 89 f3 4c 89 f2 e8 ?? ?? ?? ?? a8 01 ?? ?? 48 8b [0-18] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

