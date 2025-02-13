rule TrojanDownloader_Win64_Malgentz_AT_2147922418_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Malgentz.AT!MTB"
        threat_id = "2147922418"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Malgentz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {12 1c 1d cf 07 05 d2 ee 86 63 4b b0 38 50 57 b2 13 8e 01 2d c8 ba 2e ef 04 81 d0 be 71 a4 a6 ed fa 04 1c d9 44 56 c7 b6 b8 09 83 79 3d a4 59 48 fe f4 f4 8d e9 43 64 21 1e ae 40 15 d2 77 b8 ad}  //weight: 1, accuracy: High
        $x_1_2 = {f1 81 54 fe de eb 43 4d e4 8a 8f 4e 84 2c 15 50 7d 9d 53 dd f4 ba c1 91 31 50 80 54 f1 d2 d7 50 7c 5a a9 84 58 9d a0 7b 8b 5c ee a7 98 ed c5 e9 42 d8 6d 83 81 3a 93 ee c5 fb 8c c0 24 55 d5 f6}  //weight: 1, accuracy: High
        $x_1_3 = {7c 70 bc d3 69 23 c2 b8 b2 ad 3b d4 cc 08 bd 42 1d 38 61 71 8a 69 b3 bc 54 02 d7 5d f9 46 ea c2 73 61 ba 8f 7a 3f 50 56 83 a8 62 86 ad 8a 45 48 99 a7 f5 a2 b3 e2 bd bf 56 e9 5a 3c 65 f7 24 49 35 f5 f4 18}  //weight: 1, accuracy: High
        $n_100_4 = "Purple Pen" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

