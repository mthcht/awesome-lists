rule VirTool_Win64_Pelodesz_A_2147974410_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Pelodesz.A"
        threat_id = "2147974410"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Pelodesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c8 ba 0e 00 00 00 ff ?? ?? ?? ?? ?? 48 8b d7 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 bd 58 04 00 00 48 8b 85 30 11 00 00 48 2b 85 28 11 00 00 48 2d 09 20 00 00 48 89 85 48 11 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 44 24 20 41 b9 20 00 00 00 [0-20] 48 8b 8d 38 04 00 00 66 0f 73 df 08 66 48 0f 7e f8 ff ?? 8b d8 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

