rule Trojan_Win32_TiltBreakz_A_2147923633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TiltBreakz.A!MTB"
        threat_id = "2147923633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TiltBreakz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 61 f0 9d e0 8d 0e 07 94 c3 a6 67 05 28 a4 b4 06 69 fa 34 40 cb 77 e2 36 1e db 6b 08 43 76 b7 88 b8 69 a0 60 9b 68 76 0d f8 b4 53 45 b9 e6 15 30 d5 63 a9 82 9c 44 95 52 04 6c f2 b6 fd 72 87 68 82 5c a1 10 99 76 ee bd 64 da 6d af c1 3a 4b 64 12 d0 46 a1 63 ce 92 a9 fe 39 8d 28 60 a5 d9 ad cd 23 36 41 5e}  //weight: 1, accuracy: High
        $x_1_2 = {32 43 59 01 28 ac 4d de f4 b0 e5 0f 5f 83 c2 62 88 d3 93 ed 4d 93 64 1f 5d d0 a7 5c 6e 33 b0 f7 b9 de a0 e6 79 c2 b4 87 dd 53 2a eb 82 56 66 85 05 0e 60 c3 d3 84 a4 5b e1 f5 45 22 b4 17 ce 52 73 cf 9c 8c 4a 14 15 ac 45 65 35 e2 e3 b9 08 e4 69 80 cc fb 57 63 90 01 cd c8 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

