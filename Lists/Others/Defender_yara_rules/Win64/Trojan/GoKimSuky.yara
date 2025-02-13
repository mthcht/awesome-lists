rule Trojan_Win64_GoKimSuky_A_2147918854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoKimSuky.A!MTB"
        threat_id = "2147918854"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoKimSuky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {36 37 e0 60 f5 77 94 42 30 63 85 5e cd d3 9d 0f 0e 64 1f 91 d5 6d a4 c1 62 9f b7 d3 79 df 6e 92 32 a3 15 56 5d 5c 96 49 2e 60 05 9e 74 cb d7 2d c1 f0 3f 25 44 07 64 3e 4e 89 7a 29 ff 32 84 22 a2 60 ec c8 3d 38 b4 ee c5 52 1c 09 07 2d 47 a0 a1 ac 59 c4 dd 70 be b0 3c 49 18 82 56 51 8b 1c 3d 5b 6b 10 92 45 f7 6d da 47 c0 5d 46 83 1a d4 3b e2 54 09 d1 53 d5 2a ab 51 87 a5 31 18 09 fe be 09 13 8b}  //weight: 1, accuracy: High
        $x_1_2 = {d1 cd 66 41 81 fb cd 76 66 85 d1 81 ed 46 41 14 23 f7 dd 66 44 85 cd 57 40 d2 e7 31 2c 24 49 0b fc 66 0f ba e7 a9 45 3a fe 5f f9 48 63 ed f7 c4 cf 02 f1 26 66 44 85 e4 4c 03 d5}  //weight: 1, accuracy: High
        $x_1_3 = {44 33 cd f9 40 f6 c5 99 41 81 e9 5a 09 8c 46 41 81 f1 f6 1c 36 51 41 0f c9 f5 49 81 fa 90 33 c9 61 41 81 e9 5d 35 be 5d 66 41 3b cc 66 81 fb 7e 15 55 44 31 0c 24 66 0f ba f5 3a 40 80 c5 f8 66 d3 d5 5d 4d 63 c9 40 3a f0 45 84 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

