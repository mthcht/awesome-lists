rule VirTool_Win64_Pedesz_A_2147971787_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Pedesz.A"
        threat_id = "2147971787"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Pedesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 74 24 58 ?? ?? ?? ?? ?? 48 89 74 24 50 ?? ?? ?? ?? ?? 48 89 74 24 48 41 b9 30 00 01 00 48 89 74 24 40 48 8b cf 48 89 44 24 38 89 74 24 30 c7 44 24 28 03 00 00 00 c7 44 24 20 01 00 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 74 24 30 ?? ?? ?? ?? ?? ?? ?? c7 44 24 28 02 00 00 00 45 33 c9 45 33 c0 c7 44 24 20 02 00 00 00 ba 00 00 00 40 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

