rule Trojan_Win32_Lycaon_Z_2147949417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lycaon.Z!MTB"
        threat_id = "2147949417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lycaon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {95 de f7 ff ff b8 65 00 00 00 66 89 85 e0 f7 ff ff b9 6c 00 00 00 66 89 8d e2 f7 ff ff ba 33 00 00 00 66 89 95 e4 f7 ff ff b8 32 00 00 00 66 89 85 e6 f7 ff ff b9 2e 00 00 00 66 89 8d e8 f7 ff}  //weight: 1, accuracy: High
        $x_1_2 = {95 9c fb ff ff 83 c2 02 89 95 9c fb ff ff 66 8b 85 86 fa ff ff 66 89 85 60 ff ff ff 8b 8d 98 fb ff ff 66 8b 11 66 89 95 84 fa ff ff 8b 85 98 fb ff ff 83 c0 02 89 85 98 fb ff ff 66 8b 8d 84 fa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lycaon_ZZ_2147949418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lycaon.ZZ!MTB"
        threat_id = "2147949418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lycaon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 50 50 6a 05 8d 4d f4 51 6a 01 8d 8d 44 e5 ff ff 51 50 ff b5 20 e5 ff ff 43 ff 85 40 e5 ff ff ff 15 78 a0 48 00 8b f0 85 f6 0f 84 3d 04 00 00 6a 00 8d 85 2c e5 ff ff 50 56 8d 45 f4 50 8b 85 24 e5 ff ff 8b 00 ff 34 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lycaon_Y_2147949419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lycaon.Y!MTB"
        threat_id = "2147949419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lycaon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 2b c8 8b 95 c4 fd ff ff 81 c2 8f 79 1a 1b 33 d1 0f af 95 c8 fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lycaon_C_2147949420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lycaon.C!MTB"
        threat_id = "2147949420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lycaon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b4 21 80 f8 3c c0 10 00 8b 8d ac fe ff ff 8b 95 08 fa ff ff 8b 85 64 ff ff ff 03 04 8a 89 85 a8 fe ff ff 8b 8d ac fe ff ff 8b 95 04 fa ff ff 0f b7 04 4a 8b 8d 00 fa ff ff 8b 95 64 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lycaon_GPKA_2147972153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lycaon.GPKA!MTB"
        threat_id = "2147972153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lycaon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5a b8 4d 00 00 00 66 89 85 e0 df ff ff b9 42 00 00 00 66 89 8d e2 df ff ff ba 53 00 00 00 66 89 95 e4 df ff ff b8 65 00 00 00 66 89 85 e6 df ff ff b9 72 00 00 00 66 89 8d e8 df ff ff ba 76 00 00 00 66 89 95 ea df ff ff b8 69 00 00 00 66 89 85 ec df ff ff b9 63 00 00 00 66 89 8d ee df ff ff ba 65 00 00 00 66 89 95 f0 df ff ff b8 2e 00 00 00 66 89 85 f2 df}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lycaon_GPKD_2147972154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lycaon.GPKD!MTB"
        threat_id = "2147972154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lycaon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8e bf d0 bf 76 cd d3 be 8e bf d6 bf e1 cd d3 be 0f b8 d7 bf 4b cd d3 be 0f b8 d0 bf 44 cd d3 be ca 93 d7 bf 17 cd d3 be 46 50 79 be 4a cd d3 be}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lycaon_GPKE_2147972155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lycaon.GPKE!MTB"
        threat_id = "2147972155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lycaon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b9 95 9e 62 8a c9 63 62 da bc 67 63 9d c9 63 62 da bc 60 63 93 c9 63 62 da bc 66 63 d3 c9 63 62 5b bb 67 63 96 c9 63 62 88 c9 63 62 8e c9 63 62}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lycaon_GPKF_2147972412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lycaon.GPKF!MTB"
        threat_id = "2147972412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lycaon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 7b 0b 00 8e 75 0f 00 e6 94 17 00 a6 b0 16 00 fe aa 0c 00 e8 d8 18 00 3a 14 0d 00 3a 04 0c 00 90 e6 14 00 00 00 00 00 02 36 11 00 42 e5 15 00}  //weight: 10, accuracy: High
        $x_10_2 = {ff 74 24 28 9d 48 8d 64 24 30 e8 60 b0 18 00 ec 20 be 2d e4 dc 91 57 a8 5b a0 2d 54 dd 1b 8e fa 0a a5 d2 1b b6 79 09 cc 6d b6 f4 b9 2f e4 a9 4d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

