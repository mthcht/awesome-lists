rule Trojan_Win32_ShipUp_DSK_2147753716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShipUp.DSK!MTB"
        threat_id = "2147753716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShipUp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 f8 8b 02 33 45 ?? 8b 4d f8 89 01 c7 45 ?? 8e c3 66 00 8b e5 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShipUp_BK_2147852483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShipUp.BK!MTB"
        threat_id = "2147852483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShipUp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8c 79 15 cc 8d cb 44 b0 ee 62 a1 29 5e 68 22 63 c4 23 8d 27 18 ab 32 2a 1f a1 3e 98 7b 73 a8 07 21 48 ee a9 d8 0e 49 97 00 66 cb 93 6e 05 24 e7 a6 7e 00 d4 9c 5e f5 98 57 0f e1 2b f7 bf 20 33 da 99 1d 67 07 fc c4 a0 37 dd b0 12 5c f0 b8 00 82 19 ca 89 ff 49 da a2 0e 77 0e c0 7f 67 58 ba f0 48 df 85}  //weight: 1, accuracy: High
        $x_1_2 = {b9 79 37 9e e9 4e 69 35 da 02 f1 e1 2a 8f a7 66 27 5c d4 0a 32 81 69 02 58 43 da 04 d0 01 14 7a 06 0c a0 b2 37 1c 2d 11 ac 8b 95 60 b0 13 f9 8e 7a 7e 46 09 86 d9 50 f5 03 02 07 e5 14 76 d3 a8 2c 4b 46 dc 56 c6 0d 88 24 d8 e0 c6 c8 ed 02 60 b0 52 25 52 26 03 0c ff c3 02 b1 8a 38}  //weight: 1, accuracy: High
        $x_1_3 = {94 f8 43 f7 4a bd 09 92 b2 11 84 09 c7 f3 85 21 e7 3e a7 c6 b1 d8 eb 6a cd 2a 2a fa 17 d6 b8 ea a0 21 fa bf 4b 01 ca 9b 6a ee 8b 25 c6 f6 95 3a 09 f8 fd 97 d8 ff 97 cc c9 2d cf 40 e6 c8 98 33 97 16 9f d2 b3 ea 29 af 2a bd 2b 96 ff 64 fd bc 39 2d 12 54 24 c1 e8}  //weight: 1, accuracy: High
        $x_1_4 = {d7 b4 09 92 e2 93 a6 80 15 38 53 4d c7 ea b6 00 63 b5 2f 76 39 66 ef 2b 1f 06 78 6a 80 9a fb 97 7a f6 14 38 a1 ca 00 3e 7b 1f 9b 87 f5 3f 00 9f 5f df 02 05 3b 98 16 17 04 d0 36 00 65 0b a0 8c 14 4d 00 ea fc bc c4 79 f2 46 a2 00 cf 11 8e 37 42 93 4c 2f 01 84 ae a1 f8 fd f3 f7 ec 54 db}  //weight: 1, accuracy: High
        $x_2_5 = ".boot" ascii //weight: 2
        $x_2_6 = ".themida" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ShipUp_GNW_2147852751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShipUp.GNW!MTB"
        threat_id = "2147852751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShipUp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 07 d2 ed 66 81 fc ee 14 0b d4 8b 57 04 66 0f be c8 c1 f1 f5 8d bf ?? ?? ?? ?? 66 f7 d1 d3 e1 36 89 10 80 ed 1f 8d b6 ?? ?? ?? ?? 0b cb 8b 0e 33 cb c1 c1 03 e9}  //weight: 10, accuracy: Low
        $x_1_2 = ".vmp2" ascii //weight: 1
        $x_1_3 = "n7PNdhhteS/C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShipUp_GMQ_2147892858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShipUp.GMQ!MTB"
        threat_id = "2147892858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShipUp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 fa 23 6e e8 2d ?? ?? ?? ?? 93 34 9e c1 66 eb 76 48}  //weight: 10, accuracy: Low
        $x_1_2 = "@.themida" ascii //weight: 1
        $x_1_3 = "rcse0uni8" ascii //weight: 1
        $x_1_4 = "IeESi.Wi@i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShipUp_GMX_2147893310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShipUp.GMX!MTB"
        threat_id = "2147893310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShipUp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c4 fe c2 32 da 66 1b c5 80 ec c8 66 2b c6 88 0c 14 66 0f ba f8 ?? fe c8 8b 06}  //weight: 10, accuracy: Low
        $x_1_2 = "uZT2gwARrD" ascii //weight: 1
        $x_1_3 = ".vmp0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShipUp_GZY_2147906309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShipUp.GZY!MTB"
        threat_id = "2147906309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShipUp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {30 00 00 68 ae 0c 02 00 6a 00}  //weight: 5, accuracy: High
        $x_5_2 = {1e 32 00 40 c6 05 ?? ?? ?? ?? ?? 0b dd f3 7e}  //weight: 5, accuracy: Low
        $x_1_3 = "bfpemvhu.vcd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShipUp_GZY_2147906309_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShipUp.GZY!MTB"
        threat_id = "2147906309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShipUp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 c4 89 55 cc 8b 45 dc 89 45 fc 8b 4d c8 89 4d ec 8b 55 c4 89 55 f4 8b 45 c4 89 45 d8 8b 4d ec 89 4d e0 8b 55 d8 89 55 f8 8b 45 f8 8b 08 33 4d e0 8b 55 f8 89 0a c7 45 c0 41 3c 00 00 8b e5 5d c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShipUp_GZN_2147907953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShipUp.GZN!MTB"
        threat_id = "2147907953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShipUp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 f7 de 55 44 31 34 24 5d 48 3b c5 44 84 ee 4d}  //weight: 5, accuracy: High
        $x_5_2 = {26 32 19 54 94 56 b7 2c b3 11 81 b3 ?? ?? ?? ?? 6c f3 48 84 31 9b ?? ?? ?? ?? 48 13 23 13 29}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShipUp_ASF_2147908978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShipUp.ASF!MTB"
        threat_id = "2147908978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShipUp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 f7 d2 8d bf fc ff ff ff 8b 17 66 f7 c2 4c 53 f5 33 d3 f8 0f ca f9 c1 ca 03 e9 d6 3f 07 00 89 55 04 b9 c5 69 e5 57 89 45 08 0f bf cd e9}  //weight: 1, accuracy: High
        $x_1_2 = {81 f2 2f 45 12 62 66 f7 c6 59 1c 85 d2 f7 d2 81 f2 69 70 62 50 85 cb 33 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

