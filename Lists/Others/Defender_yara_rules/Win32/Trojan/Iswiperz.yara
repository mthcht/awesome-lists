rule Trojan_Win32_Iswiperz_AB_2147924173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iswiperz.AB!MTB"
        threat_id = "2147924173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iswiperz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {79 34 9c 34 b0 34 32 35 64 35 8e 35 a0 35 aa 35 cc 35 ed 35 5a 36 80 36 a7 36 c8 36 43 37 69 37 ?? 37 af 37 6b 38 9b 38 ec 38 21 39 71 39 92 39 63 3a 89 3a 07 3b 81 3b 8b 3b e0 3b 8c 3d 93 3d 30 3e 3f 3e d6 3e e8 3e ee 3e c3 3f c9 3f e9 3f 00 a0 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {47 36 ee 36 4d 37 a8 37 16 38 35 38 66 38 be 39 f8 3a 13 3b 29 3b 3f 3b 47 3b 40 3f 00 00 00 50 01 00 38 00 00 00 43 30 73 30 36 33 3b 33 4d 33 6b 33 7f 33 85 33 2d 34 70 34 a3 34 d2 34 42 38 b1 38 d6 38 12 3a 41 3b c7 3b e4 3b 01 3c 1e 3c 3b 3c 65 3c 00 00 00 60 01 00 4c 01 00 00 3c 31 48 31 54 31 58 31 5c 31 60 31 64 31 68 31 74 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

