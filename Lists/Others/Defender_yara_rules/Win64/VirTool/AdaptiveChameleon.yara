rule VirTool_Win64_AdaptiveChameleon_B_2147947851_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/AdaptiveChameleon.B"
        threat_id = "2147947851"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "AdaptiveChameleon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 10 0f ca 89 d1 48 8b 44 24 28 48 8b 5c 24 30 e8 ?? ?? ?? ?? 48 83 c4 18 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 08 48 8b 44 24 58 48 8b 5c 24 40 41 b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

