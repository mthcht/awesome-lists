rule VirTool_Win64_Sheledesz_A_2147961814_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Sheledesz.A"
        threat_id = "2147961814"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Sheledesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 58 33 f6 c7 44 24 40 ?? ?? ?? ?? 48 89 74 24 30 ?? ?? ?? ?? ?? ?? ?? c7 44 24 28 80 00 00 00 45 33 c9 ba 00 00 00 80 c7 44 24 20 03 00 00 00 41 b8 01 00 00 00 48 89 74 24 48 89 74 24 50 89 74 24 54 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b ce 44 8b c0 85 c0 ?? ?? 48 8b d7 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 44 0c 40 30 02 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b ce 48 83 f8 03 48 0f 42 c8 49 83 e8 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

