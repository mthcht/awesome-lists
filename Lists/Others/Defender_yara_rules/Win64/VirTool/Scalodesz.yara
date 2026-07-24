rule VirTool_Win64_Scalodesz_A_2147974412_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Scalodesz.A"
        threat_id = "2147974412"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Scalodesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 48 18 48 8b 94 24 e8 00 00 00 48 39 ca ?? ?? ?? ?? ?? ?? 8b 70 1c 48 39 f1 ?? ?? ?? ?? ?? ?? 48 89 84 24 50 01 00 00 48 89 b4 24 38 01 00 00 48 89 8c 24 30 01 00 00 48 89 f1 48 29 d6 48 c1 fe 3f 48 21 ce}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 8c 24 b0 00 00 00 48 89 48 08 48 c7 40 10 00 30 00 00 48 c7 40 18 40 00 00 00 48 89 c3 b9 04 00 00 00 48 89 cf 48 8b 44 24 58 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

