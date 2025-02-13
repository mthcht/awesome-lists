rule Ransom_Win32_Lyposit_A_2147662967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lyposit.A"
        threat_id = "2147662967"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lyposit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 7d f8 8d 43 02 66 3b 4d fc 73 0e 2b f8 8a 08 80 f1 cc 88 0c 07 40 4e 75 f4}  //weight: 10, accuracy: High
        $x_10_2 = {0f b6 0e 83 c6 04 8a 16 c1 e0 08 03 c1 8b cb 84 d2 74 0c 2b f3 88 11 41 8a 14 0e}  //weight: 10, accuracy: High
        $x_2_3 = {69 c9 69 90 00 00 c1 e8 10 03 c1 8b 4a 04 56 0f b7 f1 69 f6 50 46 00 00 89 42 08 c1 e9 10 03 ce c1 e0 10 89 4a 04}  //weight: 2, accuracy: High
        $x_1_4 = {fe 5f bc 07 fa 5f 04 b8 07 a1 e5 00}  //weight: 1, accuracy: High
        $x_1_5 = {fd ff b8 05 f6 ff 51 be 42 0c 51 be 42 0e 51 be 42 7b 46 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Lyposit_B_2147670482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lyposit.B"
        threat_id = "2147670482"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lyposit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {0f b7 0b 81 f1 ef be 00 00 0f b7 c9 89 4d d8 89 45 e4 83 7d e0 00 74 2f 0f b7 c9 8b d1 c1 ea 03 c1 e1 0d}  //weight: 100, accuracy: High
        $x_100_2 = {89 75 fc 66 3b 75 08 73 27 8a 01 34 cc 88 02 46 41 89 4d e4 42 89 55 e0 eb e9}  //weight: 100, accuracy: High
        $x_4_3 = {fe ff ff 59 3c 03 74 15 3c 02 74 0d 68 a0 bb 0d 00 ff 15}  //weight: 4, accuracy: High
        $x_4_4 = {6a 7c 8b cf e8 ?? ?? 00 00 83 c4 0c 88 45 e7 3c 03 0f 82 b0 01 00 00 8a 5d 08 89 7d dc 84 db 74 15 8b 7d dc 57 ff 15}  //weight: 4, accuracy: Low
        $x_2_5 = {fd 3f 5a 05 bc 3f fe bd 45 83 ac e6 1e 9d f3 bc 57 91 f3 a4 08 99 f3 af 5f 9a fd ac 1f 90 f9 a4}  //weight: 2, accuracy: High
        $x_2_6 = {51 89 18 bc 45 81 15 ad 1e 9c 0b ab 1f 92 1d e3 4c 9b 0d b8 40 c9 56 e3 59 84 11 aa 08 96 16 a4}  //weight: 2, accuracy: High
        $x_2_7 = {ff 3f 5f 0b ed 3f c0 a8 55 87 e4 a6 41 96 cf 8a 5a 90 e1 a8 40 9c f5 b3 70 fb 25}  //weight: 2, accuracy: High
        $x_2_8 = {fe 5f ae 06 ec 5f 31 a5 54 e7 15 ab 40 f6 3e 87 5b f0 10 a5 41 fc 04 be 36 a7 7d}  //weight: 2, accuracy: High
        $x_2_9 = {40 77 0f 2d 40 e8 ac aa f8 cc a2 be e9 e7 8e a5 ef c9 ac bf e3 dd b7 90 db d2 ad a8 e3 cc b0 90}  //weight: 2, accuracy: High
        $x_2_10 = {5a 70 20 a9 40 7c 34 b2 6f 44 3b a8 57 7c 25 b5 6f 50 27 b4 41 76 3c b2 65 76 20 b5 5a 7c 3c 9a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Lyposit_C_2147681488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lyposit.C"
        threat_id = "2147681488"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lyposit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 51 38 3b c3 7c ?? 83 7d ?? 06 75 ?? 8b 45 e4 8b 08 50 ff 51 24 8b 45 0c 89 30}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 70 78 03 f2 8b 7e 20 03 fa 8b 5e 24 03 da 8b 46 1c 03 c2}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 08 8b 40 10 83 c4 14 be 01 00 00 80 83 f8 ff 74 07 3d 00 30 00 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Lyposit_D_2147684584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lyposit.D"
        threat_id = "2147684584"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lyposit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 7d d4 6c 80 7d fe 75 10 81 7d d8 a3 1f c3 d9 75 07 c7 45 e4 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 d8 8b 45 d8 c7 00 0c b1 37 13 6a 10}  //weight: 1, accuracy: High
        $x_1_3 = {33 45 d8 33 55 dc 89 45 d8 89 55 dc 8b 45 e4 0f b6 08 83 e1 3f}  //weight: 1, accuracy: High
        $x_1_4 = {eb 26 c1 c2 06 8b c2 24 3f 3c 3e 73 12 3c 34 73 0a 04 41 3c 5b}  //weight: 1, accuracy: High
        $x_1_5 = {0f be 04 10 8b 4d 08 03 4d f8 0f be 09 33 c1 88 45 f6 8b 45 f8 33 d2 6a 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

