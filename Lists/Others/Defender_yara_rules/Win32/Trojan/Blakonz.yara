rule Trojan_Win32_Blakonz_A_2147915897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blakonz.A!MTB"
        threat_id = "2147915897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blakonz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 60 c4 7f 5f 80 15 ac 71 ba f9 79 43 df 9f b6 62 e2 a3 59 f3 5f 11 6c 07 01 13 9e 65 96 61 e7 58 f5 a5 c8 fc c0 f7 a4 1c b1 9b 63 28 a3 57 c2 fe 27 49 23 65 f7 0c 98 c7 1b b9 43 69 3f 61 20 74 9e ba f0 fb 8d 92 d4 36 23 b3 7e d9 f2 c5 60 03 f0 54 b0 90 d8 52 20 fe bc f1 5a 0e 62 61 f0 53 26 b6 2b b9 68 5b 8e 2b 51 db a2 fd e2 40 72 31 f1 fa 44 b1 11 0c 31 86 11 d4 ea 8e 2c 0f 93 cc 6f e1 88 6f 5f a9 ac 85 28 aa b3 1c ee 82 f2 0d d3 d1 48 86 33 aa 93 a7 fb b1 d1 3b 3b 18 71 e5 67 f5 9b 31 2d 6f 56 56 46 56 42 1b 2b b2 69 1d 3b 7e cb f9 f5 ee 87 bb d5 92 73 08 26 9e 03 16 c6 57 3c 7c 84 77 0e bd 99 9f 5a 73 79 f5 50 93 b0 55 91 b1 a7 8a 3a de d1 69 95 24 8a ad 31 1d 67 5f af a7 3a 86 0f 95 e0 ec 16 51 6c 22 df c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

