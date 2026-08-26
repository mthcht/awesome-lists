rule VirTool_Win64_Stelesz_A_2147977020_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Stelesz.A"
        threat_id = "2147977020"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Stelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 38 33 db ?? ?? ?? ?? ?? ?? ?? 48 89 5c 24 30 ff ?? ?? ?? ?? ?? 48 85 c0 [0-24] 48 8b c8 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 30 48 85 c0 [0-24] e8 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 41 b9 14 00 00 00 48 89 5c 24 20 48 8b c8 [0-18] ff ?? ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8b 44 24 30 45 33 c9 33 d2 48 89 5c 24 28 33 c9 89 5c 24 20 ff ?? ?? ?? ?? ?? 48 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

