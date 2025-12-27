rule VirTool_Win64_Senjesz_A_2147955143_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Senjesz.A"
        threat_id = "2147955143"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Senjesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 2b e0 48 8b ?? ?? ?? ?? ?? 48 33 c4 48 89 84 24 20 20 00 00 ba 00 10 00 00 41 b9 04 00 00 00 44 8b c2 33 c9 ?? ?? ?? ?? ?? ?? 41 b8 ff ff 00 00 [0-24] 33 c0 48 8b 8c 24 20 20 00 00 48 33 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

