rule VirTool_Win64_Emoresz_A_2147963239_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Emoresz.A"
        threat_id = "2147963239"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Emoresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 31 c0 ff ?? 48 89 c6 48 b8 00 00 00 00 00 00 00 80 ?? ?? ?? ?? ?? 80 7f 01 8b ?? ?? 80 7f 02 d1 ?? ?? 80 7f 03 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 17 48 8b 47 08 48 89 d1 48 f7 d9 ?? ?? ?? ?? ?? ?? 48 c7 85 e8 01 00 00 00 00 00 00 4c 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

