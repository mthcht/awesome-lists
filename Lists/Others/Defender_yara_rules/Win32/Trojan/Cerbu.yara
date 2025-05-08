rule Trojan_Win32_Cerbu_SIB_2147812820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerbu.SIB!MTB"
        threat_id = "2147812820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 01 8b 55 ?? 03 55 ?? 0f b6 02 05 ?? ?? ?? ?? 8b 4d 00 03 4d 01 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {88 01 8b 55 ?? 03 55 ?? 8a 02 2c ?? 8b 4d ?? 03 4d ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 02 35 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4d 08 0f be 11 85 d2 74 ?? 8b 45 ?? c1 e0 05 03 45 01 8b 4d 08 0f be 11 03 c2 89 45 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cerbu_RPQ_2147830744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerbu.RPQ!MTB"
        threat_id = "2147830744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 75 e4 8b 45 d8 03 34 90 03 75 fc 8b 4d ec 8b 11 2b d6 8b 45 ec 89 10 8b 4d f4 8b 55 ec 8b 02 89 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cerbu_RPY_2147852903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerbu.RPY!MTB"
        threat_id = "2147852903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8a d4 89 15 1c f3 45 01 8b c8 81 e1 ff 00 00 00 89 0d 18 f3 45 01 c1 e1 08 03 ca 89 0d 14 f3 45 01 c1 e8 10 a3 10 f3 45 01 33 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cerbu_MBHS_2147852941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerbu.MBHS!MTB"
        threat_id = "2147852941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8a d4 89 15 1c 03 46 01 8b c8 81 e1 ff 00 00 00 89 0d 18 03 46 01 c1 e1 08 03 ca 89 0d 14 03 46 01 c1 e8 10 a3 10 03 46 01 33 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cerbu_NE_2147901008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerbu.NE!MTB"
        threat_id = "2147901008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7c b4 33 db 8b 0d ?? ?? ?? ?? 8d 04 db 83 3c 81 ?? 8d 34 81 75 4d 85 db}  //weight: 5, accuracy: Low
        $x_1_2 = "fuyunxshuo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cerbu_PAB_2147923504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerbu.PAB!MTB"
        threat_id = "2147923504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {64 ff 30 64 89 20 e8 ?? ?? ?? ?? 8d 45 fc 50 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 e8}  //weight: 3, accuracy: Low
        $x_2_2 = "bpcgyufr" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cerbu_AMDC_2147931938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerbu.AMDC!MTB"
        threat_id = "2147931938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 17 89 d8 88 c0 d9 ff ?? ?? 80 2f ?? 80 07 ?? 89 d8 88 c0 d9 ff ?? ?? 47 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cerbu_BAA_2147936693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerbu.BAA!MTB"
        threat_id = "2147936693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 00 83 c0 01 89 45 00 8b 4d 50 0f b7 51 06 39 55 00 0f 8c}  //weight: 2, accuracy: High
        $x_2_2 = {6b 45 00 28 03 45 60 b9 01 00 00 00 c1 e1 00 8a 14 08 88 55 33 0f be 45 33 83 f8 72 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cerbu_MBY_2147940963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cerbu.MBY!MTB"
        threat_id = "2147940963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c2 8b ce 81 fa ?? ?? ?? 00 0f 43 c8 4e 8a 01 88 04 1a 42 8b 44 24 0c 81 fa ?? ?? ?? 00 72 e0}  //weight: 2, accuracy: Low
        $x_1_2 = {8d 0c 1a 8d 42 01 42 30 01 81 fa ?? ?? ?? 00 72 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

