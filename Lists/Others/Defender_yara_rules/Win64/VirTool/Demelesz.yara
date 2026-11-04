rule VirTool_Win64_Demelesz_A_2147981495_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Demelesz.A"
        threat_id = "2147981495"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Demelesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 ef 49 0f 45 fc 48 63 43 08 48 01 c7 49 63 76 08 48 63 43 04 48 01 c6 4c 01 f6 48 63 4b 0c f3 a4}  //weight: 1, accuracy: High
        $x_1_2 = {48 63 d0 41 b9 40 00 00 00 41 b8 00 30 10 00 b9 00 00 00 00 ff ?? 48 89 c6 ?? ?? ?? ?? ?? 4d 89 e1 49 89 c0 48 89 da 48 89 f9 e8 ?? ?? ?? ?? b8 0d ae e0 cc 41 89 c0 48 89 f2 48 89 d9 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

