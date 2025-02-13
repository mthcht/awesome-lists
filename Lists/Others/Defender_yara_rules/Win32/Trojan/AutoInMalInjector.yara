rule Trojan_Win32_AutoInMalInjector_A_2147917262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInMalInjector.A!MTB"
        threat_id = "2147917262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInMalInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d4 fd 28 66 66 c5 27 c8 a3 ca 28 ba b2 fc 5b f5 5c 6f a2 6f b9 09 6d ca a9 3b 93 89 30 07 f7 d7 dc 6a f4 24 5a aa c7 2a ff d9 0f 1b a6 3f 07 43 39 52 de d7 57 41 6f 31 f0 0c e1 33 df 17 0c 56 cd a8 62 e6 4e ee d7 ef 94 e9 5e e8 74 b7 66 9a 21 27 2e dd f9 3b 6d 23 eb 39 74 87 9e da 75 cc 81 3f db 39 67 a0 cf b8 18 39 84 61 a2 5a c0 22 ad dc 11 08 0f 97 9d 07 c7 6f a5 83 90 64 53 cd dd 1c 4a 86 ef b9 8c 76 6b b9 32 5b}  //weight: 1, accuracy: High
        $x_1_2 = {78 e4 a9 f2 8c fc cd a0 24 bd c7 57 35 f9 17 a2 8c c5 8e f7 7e fb 25 26 6a 46 da a6 82 38 ac 1b f9 3a a3 78 9f 14 a5 58 7f 54 8b ad 7e bb 4e 59 9a 26 ef f2 06 9d e4 e1 f3 dd c3 c8 53 8d 0c 9c c1 3a b9 38 e6 3d f0 17 2f dc 25 77 44 05 3a 1b 42 92 b7 3e 88 7b e4 0e b3 a9 bd a7 3f d1 b0 ce cc 4f a6 4d 39 f0 38 99 8e 16 b0 68 8c 8f e9 f4 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

