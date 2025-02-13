rule VirTool_Win64_FreizLoaz_A_2147835319_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/FreizLoaz.A!MTB"
        threat_id = "2147835319"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "FreizLoaz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {dc 1f 0a 04 0b 07 10 15 18 02 02 02 16 04 0a dd 06 0a eb 18 0a a8 02 08 c7 02 04 c8 02 04 c8 16 01 c7 16 09 a2 1d 05 cf 1e 0c d0 1e 12 02 14 0a 0d 01 0f d9 1e 05 ea 1e 0f 01 0c 02 1a c9 1e 09 c8 1e 0f 02 0f cb 1e 28 00 0a 22 05 05 08 05 07 06}  //weight: 1, accuracy: High
        $x_1_2 = {02 05 91 0a 05 ?? 0a 07 06 0e 95 0a 10 9a 0a 03 99 0a 06 94 0a 02 93 0a 17 92 0a 1e 91 0a 07 94 0a 01 ad 0c 14 00 0c 18 05 04 02 0a 02}  //weight: 1, accuracy: Low
        $x_1_3 = {05 04 07 06 1b c3 0d 01 11 05 02 09 12 09 c2 0d 0f c7 0f 04 c8 0f 1a 02 05 e7 11 05 ea 11 10 e5 11 09 e6 11 10 d9 11 0f da 11 09 04 10 d9 0d 0c c8 0d 4a 00 02 0e 80 01 6f 7f 01 80 01 0e 7f 19 00 3c 29 37 14 38 05 37 04 38 38 37 0e 38 19 00 d6 12 18 02 11 fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

