rule Trojan_Win32_CobalStrikepz_A_2147917996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobalStrikepz.A!MTB"
        threat_id = "2147917996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobalStrikepz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 27 14 95 ff 2b 1b 95 ff 32 74 91 0c 8c 7c ba 30 7d f0 a5 9a 07 92 22 70 ae 19 6b 89 c4 19 6b 89 ee 25 ca 56 04 26 ca 56 f2 31 4c 35 53 85 ce 77 8d 87 4a 5f a6 6a 44 c4 63 59 25 2e 3d 05 17 8e b6 b3 39 c8 b2 36 0f 13 c2 48 95 19 71 6f c2 65 89 f4 5d 55 06 3e d6 07 2b 25 07 49 e3 7a eb c1 60 06 64 29 33 61 20 d5 58 0f 41 97 31 ad b0 b4 c0 fe c0 d8 aa fe c0 d8 83 17 51 0e f9 46 be f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

