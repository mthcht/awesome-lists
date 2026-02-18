rule VirTool_Win64_Shecoledz_A_2147963238_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shecoledz.A"
        threat_id = "2147963238"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shecoledz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff c1 48 81 f9 00 00 20 00 ?? ?? ?? ?? ?? ?? 48 89 d3 80 3a 0f ?? ?? 80 7a 01 05 ?? ?? ?? 80 7a 02 c3 ?? ?? 48 89 d8 48 83 c4 10 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 4c 24 38 48 89 44 24 40 48 8b [0-25] bf 2e 00 00 00 ?? ?? ?? ?? ?? 41 b8 01 00 00 00 4d 89 c1 66 ?? e8 ?? ?? ?? ?? 48 8b 44 24 58 48 8b 5c 24 60 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

