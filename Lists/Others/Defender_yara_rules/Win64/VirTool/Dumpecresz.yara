rule VirTool_Win64_Dumpecresz_A_2147962533_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Dumpecresz.A"
        threat_id = "2147962533"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Dumpecresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 40 48 8b 4c 24 38 31 d2 48 f7 f1 48 89 c2 48 8b 44 24 40 48 89 54 24 50 31 d2 48 f7 f1 48 8b 44 24 38 48 89 54 24 48 48 83 f8 00 0f 97 c0 0c 00 a8 01}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 8c 24 08 01 00 00 48 8b 94 24 50 01 00 00 e8 ?? ?? ?? ?? 48 89 84 24 08 01 00 00 48 8b 8c 24 00 01 00 00 48 8b 94 24 50 01 00 00 e8 ?? ?? ?? ?? 48 89 84 24 00 01 00 00 ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

