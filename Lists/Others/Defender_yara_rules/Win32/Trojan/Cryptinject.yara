rule Trojan_Win32_Cryptinject_2147729037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject!MTB"
        threat_id = "2147729037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 41 01 b9 ?? ?? ?? ?? 99 f7 f9 8b ca 8b 84 8d ?? ?? ?? ?? 03 c3 bb ?? ?? ?? ?? 99 f7 fb 8b da 8a 84 8d ?? ?? ?? ?? 8b 94 9d ?? ?? ?? ?? 89 94 8d ?? ?? ?? ?? 25 ?? ?? ?? ?? 89 84 9d ?? ?? ?? ?? 8b 84 8d ?? ?? ?? ?? 03 84 9d ?? ?? ?? ?? be}  //weight: 1, accuracy: Low
        $x_1_2 = {99 f7 fe 8a 84 95 ?? ?? ?? ?? 8b 55 08 8b 75 fc 30 04 32 ff 45 fc 8b 45 fc 3b 45 10 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_2147729037_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject!MTB"
        threat_id = "2147729037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 65 74 50 10 00 c7 05 ?? ?? ?? ?? 47 65 74 50 c7 05 ?? ?? ?? ?? 72 6f 63 41 c7 05 ?? ?? ?? ?? 64 64 72 65 [0-32] 68 01 [0-10] e8}  //weight: 1, accuracy: Low
        $x_1_2 = {47 65 74 54 10 00 c7 05 ?? ?? ?? ?? 47 65 74 54 c7 05 ?? ?? ?? ?? 69 63 6b 43 c7 05 ?? ?? ?? ?? 6f 75 6e 74 [0-32] 68 01 [0-10] e8}  //weight: 1, accuracy: Low
        $x_1_3 = {49 73 42 61 10 00 c7 05 ?? ?? ?? ?? 49 73 42 61 c7 05 ?? ?? ?? ?? 64 52 65 61 c7 05 ?? ?? ?? ?? 64 50 74 72 [0-32] 68 01 [0-10] e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cryptinject_DSK_2147742182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.DSK!MTB"
        threat_id = "2147742182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 85 d4 ef ff ff 8b 9d d0 ef ff ff c0 e0 06 08 85 d5 ef ff ff 8a 85 d6 ef ff ff 88 04 1f 81 3d bc ff 16 04 0e 06 00 00 75}  //weight: 2, accuracy: High
        $x_2_2 = {a1 34 89 14 04 8a 4c 18 01 88 8d d7 ef ff ff 8a 4c 18 02 8a 44 18 03 8a d8 80 e3 f0 c0 e3 02 81 3d bc ff 16 04 d3 0b 00 00 88 8d d5 ef ff ff 88 85 d4 ef ff ff 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_DSK_2147742182_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.DSK!MTB"
        threat_id = "2147742182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 10 73 ?? 8b 4d f8 8b 55 f4 8a 02 88 01 8b 4d f8 83 c1 01 89 4d f8 8b 55 f4 83 c2 01 89 55 f4 eb}  //weight: 2, accuracy: Low
        $x_1_2 = "Hfsdfgkj53" ascii //weight: 1
        $x_1_3 = "HfsdfJg42" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_CG_2147742675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.CG"
        threat_id = "2147742675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 ff 75 f0 56 e8 42 ff ff ff 89 45 e4 53 ff 75 f0 56 e8 35 ff ff ff 89 45 e0 8b 7d 08 89 f1 41 99 f7 f9 89 c2 01 fa 52 8b 55 e4 89 f1 d3 fa 01 fa 52 e8 fb fe ff ff 83 c4 20 ff 45 e8 81 7d e8 e8 07 00 00 7c ba ff 45 fc 8b 45 f8 89 f2 42 0f af c2 39 45 fc 0f 8e 6d ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {f7 e1 89 45 f4 a3 f0 6c 42 00 a1 e8 6c 42 00 31 f0 05 55 ed 00 00 a3 e8 6c 42 00 8b 3d e8 6c 42 00 89 f0 89 f9 80 c9 01 f7 e1 89 45 f0 89 c2 89 f8 2b 45 f0 b9 4b 0a 01 00 31 d2 f7 f1 89 15 e8 6c 42 00 8b 3d ec 6c 42 00 b8 99 07 01 00 89 f9 89 f2 d3 e2 01 d7 f7 e7 89 45 ec a3 ec 6c 42 00 b8 39 64 04 00 8b 0d fc 6c 42 00 31 f1 f7 e1 89 45 e8 a3 fc 6c 42 00 8b 3d e4 6c 42 00 89 f1 d3 ef 81 c7 a7 1d 01 00 89 3d e4 6c 42 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_DG_2147742724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.DG"
        threat_id = "2147742724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 10 8b 4d 0c 8b 55 08 8b 74 24 30 8b 7c 24 34 83 f8 00 89 44 24 28 89 4c 24 24 89 54 24 20 89 74 24 1c 89 7c 24 18 0f 84 90 00 00 00 e9 80 00 00 00 8b 44 24 14 b9 85 10 42 08 89 44 24 10 f7 e1 8b 44 24 10 29 d0 d1 e8 01 d0 c1 e8 04 89 c1 c1 e1 05 29 c1 f7 d9 8b 44 24 10 0f b6 8c 08 a8 42 40 00 c7 44 24 34 00 00 00 00 c7 44 24 30 5c 00 cc 14 89 e2 89 4a 0c 89 42 08 8b 4c 24 24 89 4a 04 8b 74 24 20 89 32 e8 e7 ea ff ff c7 44 24 34 00 00 00 00 c7 44 24 30 00 00 00 00 8b 44 24 10 83 c0 01 8b 4c 24 28 39 c8 89 44 24 14 74 0d}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 10 b1 ae 8a 54 24 17 28 d1 88 4c 24 27 8a 4c 04 34 0f be f1 66 89 f7 66 89 7c 44 54 83 c0 01 83 f8 20 89 44 24 10 74 c1 eb d3}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 d8 8b 4d e0 8b 55 dc 89 45 cc 89 55 c8 89 4d c4 0f 31 89 d6 89 c7 0f 31 89 d3 89 c1 b8 67 d9 bd 0a 66 8b 55 f2 66 81 c2 ec 24 66 89 55 f2 8b 55 e8 29 f9 8b 7d cc 83 ff 00 8b 7d c4 0f 44 f9 89 45 c0 8b 45 cc 83 f8 00 8b 45 c8 0f 44 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_MK_2147744508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.MK!MTB"
        threat_id = "2147744508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 ec fb ff ff 83 c2 04 88 1c 3e 88 7c 3e 01 88 4c 3e 02 83 c6 03 89 95 f0 fb ff ff 3b 10}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e8 10 30 04 0e 46 3b f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cryptinject_R_2147745277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.R!MTB"
        threat_id = "2147745277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fb f5 11 00 00 75 ?? 56 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 95 0c ef ff ff 69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 89 0d ?? ?? ?? ?? c1 e8 10 30 04 17 47 3b fb 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_PVG_2147755371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.PVG!MTB"
        threat_id = "2147755371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 8d 34 07 e8 ?? ?? ?? ?? 30 06 47 3b 7d 0c 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {69 c0 fd 43 03 00 05 c3 9e 26 00 81 ec 08 04 00 00 a3 ?? ?? ?? ?? 3d ac 61 ef 01 75 05 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_MX_2147755656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.MX!MTB"
        threat_id = "2147755656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 c1 ea 05 03 95 c8 fb ff ff 81 3d ?? ?? ?? ?? 31 09 00 00 89 95 d8 fb ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f3 07 eb dd 13 81 6d ?? 52 ef 6f 62 2d f3 32 05 00 81 6d ?? 68 19 2a 14 81 45 ?? be 08 9a 76 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cryptinject_MX_2147755656_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.MX!MTB"
        threat_id = "2147755656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f3 07 eb dd 13 81 6c 24 ?? 52 ef 6f 62 2d f3 32 05 00 81 6c 24 ?? 68 19 2a 14 81 44 24 ?? be 08 9a 76 8b 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 20 c1 ea 05 03 54 24 38 89 54 24 ?? 3d 31 09 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_MW_2147755657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.MW!MTB"
        threat_id = "2147755657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 49 00 e8 ?? ?? ?? ?? 8b 4c 24 ?? 30 04 0e b8 01 00 00 00 29 44 24 ?? 83 7c 24 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_PVA_2147758864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.PVA!MTB"
        threat_id = "2147758864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 0c 00 7c ?? e8 ?? ?? ?? ?? 0f b6 c0 8b 4d 08 03 4d 0c 0f be 11 33 d0 8b 45 08 03 45 0c 88 10 8b 4d 0c 83 e9 01 89 4d 0c eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_RAC_2147760573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.RAC!MTB"
        threat_id = "2147760573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://%s:%d/%s?type=2&hash=%s&time=%s" ascii //weight: 1
        $x_1_2 = "The NCBENUM return adapter number is: %d" ascii //weight: 1
        $x_1_3 = "www.yandex2unitedstated.dynamic-dns.net" ascii //weight: 1
        $x_1_4 = "Is vmware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_PW_2147769058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.PW!MTB"
        threat_id = "2147769058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 c2 2b f0 83 c6 04 89 35 ?? ?? ?? ?? 8b 84 39 e3 db ff ff 05 60 dd 0e 01 a3 ?? ?? ?? ?? 89 84 39 e3 db ff ff 83 c7 04 0f b7 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8b c1 8a 15 ?? ?? ?? ?? 2b c6 83 c0 04 89 45 e8 a3 ?? ?? ?? ?? 81 ff fd 24 00 00 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_PV_2147795998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.PV!MTB"
        threat_id = "2147795998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {69 c9 ac 44 01 00 2b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 8c 02 aa df ff ff 81 c1 a8 07 04 01 89 0d ?? ?? ?? ?? 89 8c 02 aa df ff ff 83 c0 04 3d 4e 21 00 00 72 0d 00 0f b6 0d ?? ?? ?? ?? 8b 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_PX_2147796673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.PX!MTB"
        threat_id = "2147796673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce 0f b6 f0 0f af f1 89 0d ?? ?? ?? ?? 8a 2d ?? ?? ?? ?? 2b f7 89 35 ?? ?? ?? ?? 8b 02 05 3c f0 0d 01 89 02 83 c2 04 a3 ?? ?? ?? ?? 8d 43 b8 02 05 ?? ?? ?? ?? 83 6c 24 10 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_PY_2147797354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.PY!MTB"
        threat_id = "2147797354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 18 2a da 8b 15 ?? ?? ?? ?? 80 eb 06 0f b7 f8 8d 86 68 f5 02 01 8b 74 24 10 83 44 24 10 04 a3 ?? ?? ?? ?? 89 06 0f b6 c3 66 2b 05 ?? ?? ?? ?? 83 6c 24 1c 01 8d 34 07 66 8b c6 0f b7 fe 89 44 24 0c 0f 85 ?? ?? ?? ?? 8d 82 3e 58 00 00 03 c6 81 3d ?? ?? ?? ?? 44 10 00 00 66 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_QA_2147799383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.QA!MTB"
        threat_id = "2147799383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 55 fc 0f b6 45 ff 33 c2 88 45 ff 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 8a 4d fc 80 c1 01 88 4d fc 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 8b 55 f0 8a 45 ff 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_QB_2147905195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.QB!MTB"
        threat_id = "2147905195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 0f b6 08 8b 45 f0 99 f7 7d ec 89 d0 89 c2 8b 45 08 01 d0 0f b6 00 31 c1 89 ca 8b 45 f4 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_YBB_2147930738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.YBB!MTB"
        threat_id = "2147930738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_11_1 = {2b d1 2b 55 e8 89 55 a0 8b 85 64 ff ff ff 33 85 6c ff ff ff 89 85 64 ff ff ff 0f b7 4d ec 0f b6 55 e0 2b ca 89}  //weight: 11, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cryptinject_YBD_2147931722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cryptinject.YBD!MTB"
        threat_id = "2147931722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptinject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 57 83 c4 04 81 ef ?? ?? ?? ?? 81 cf ?? ?? ?? ?? 81 cf ?? ?? ?? ?? 5f 51 81 c9 87 31 01 00}  //weight: 1, accuracy: Low
        $x_10_2 = {0f b6 84 15 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 0f b6 11 33 d0 8b 85 ?? ?? ?? ?? 03 85 a4 fa ff ff 88 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

