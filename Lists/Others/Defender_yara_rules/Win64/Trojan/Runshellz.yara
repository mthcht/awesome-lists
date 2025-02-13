rule Trojan_Win64_Runshellz_A_2147925909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Runshellz.A!MTB"
        threat_id = "2147925909"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Runshellz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {95 27 d9 5d 79 0d 9b 5d d1 e5 0c 64 1a 1e 3a c8 18 de 52 60 b3 df 91 95 a9 85 79 3f 73 17 87 c8 8e 82 44 65 85 bb ff 9b 21 b8 7e 32 d0 1b 7e 30 74 28 dc 20 e6 5a 7c 49 45 7b 3f 9b 2b 72 34 68 aa f3 06 38 7c 54 c4 1d d3 57 73 dc 2e e0 a4 78 ca 2b ed a1 65 b0 dc 92 96 0a 92 f7 a9 ed 25 72 fc b2 f6 22 72 88 4e c2 d4 71 9e 50 d4 cc 56 98 5e d2 c0 43 ae 60 24 f8 22}  //weight: 1, accuracy: High
        $x_1_2 = {cf 1d 53 c4 5b bd a7 d3 30 33 d8 1b ad a9 86 0f 35 89 13 7f 83 5a ba b7 02 8e 09 9d e3 04 19 ef 92 37 ce 03 98 fe 88 ca f2 b2 6b 5c a5 37 68 82 b9 da f3 99 50 7f 96 4b a8 80 a1 e3 cb 4d 68 46 d3 3d 7a 9a 96 33 ea fa bd 40 a7 5c a3 b1 bf dd e1 57 7e 7c c5 d7 48 8c 92 37 16 fe a1 4d a0 59 be c8 4e 8c 30 76 3a 17 62 6e c9 08 12 b7 96 40 1e bf 56 8b 02}  //weight: 1, accuracy: High
        $x_1_3 = {5e 48 89 c1 48 81 c6 8e 9f 06 00 48 c7 c1 86 ac 00 00 8a 16 88 13 48 ff c6 48 ff c3 e2 f4 48 8b d8 ff d3 b9 01 00 00 00 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

