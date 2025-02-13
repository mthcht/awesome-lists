rule Trojan_Win32_Loaderz_KO_2147922587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Loaderz.KO!MTB"
        threat_id = "2147922587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Loaderz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3e 31 4a 31 51 31 82 31 98 31 c2 31 cb 31 db 31 e9 31 f2 31 08 32 34 32 3a 32 42 32 49 32 59 32 5d 32 b9 32 bf 32 d7 32 dd 32 f2 32 5e 33 68 33 6e 33 79 33 82 33 90 33 95 33 a3 33 d1 33 f0 33 01 34 08 34 13 34 25 34 35 34 4e 34 62 34 6e 34 75 34 a2 34 b2 34 ec 34 f2 34 02 35 08 35 0e 35 16 35 1e 35 30 35 3d 35 49 35 50 35 59 35 87 35 92 35 99 35 a6 35 c9 35 41 36 99 36 b9 36 e1 36 f3 36 ff 36 26 37 3b 37 47 37 68 37 81 37 92 37 07 38 14 38 39 38}  //weight: 1, accuracy: High
        $x_1_2 = {3e 38 b3 38 cb 38 03 39 6b 39 aa 39 b7 39 f1 39 0d 3a 2d 3a 52 3a 7a 3a 95 3a a2 3a a9 3a c8 3a da 3a ee 3a 0b 3b 22 3b 46 3b 58 3b 5d 3b 62 3b 6d 3b 7b 3b a5 3b c0 3b ce 3b d4 3b f0 3b 23 3c 39 3c 3e 3c 46 3c 51 3c 70 3c 83 3c c5 3c ce 3c dd 3c eb 3c fa 3c 29 3d 43 3d 82 3d 9a 3d a9 3d af 3d ca 3d d0 3d db 3d e1 3d f6 3d 04 3e 65 3e c6 3e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

