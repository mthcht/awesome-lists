rule Trojan_Win64_GlassWorm_2147959907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GlassWorm!MTB"
        threat_id = "2147959907"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GlassWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 8b 14 01 48 8b 0c 02 4c 31 d1 4c 21 c1 49 31 ca 4d 89 14 01 48 31 0c 02 48 83 c0 08 48 83 f8 28 75 dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GlassWorm_AGL_2147964444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GlassWorm.AGL!MTB"
        threat_id = "2147964444"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GlassWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 f6 eb 07 40 88 3c 31 48 ff c6 48 39 f3 7e 0e 0f b6 3c 30 31 d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GlassWorm_AGW_2147967902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GlassWorm.AGW!MTB"
        threat_id = "2147967902"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GlassWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 89 c8 41 c1 e0 05 41 01 c8 41 01 d0 41 81 f0 ef be ad de 41 0f b6 4c 06 fd 44 01 c1 41 c1 e0 05 44 01 c1 81 f1 ef be ad de 41 0f b6 54 06 fe 01 ca c1 e1 05 01 ca 81 f2 ef be ad de 45 0f b6 44 06 ff 41 01 d0 c1 e2 05 41 01 d0}  //weight: 2, accuracy: High
        $x_1_2 = {4c 89 f8 48 f7 ea 49 89 d4 49 c1 f8 3f 49 b9 7b 83 2f 4c a6 0a 46 25 4d 0f af cf 49 ba 44 fa ed eb c0 39 23 4a 4c 89 f8 49 f7 e2 48 c1 f9 3f 4c 01 ca 4d 0f af c2 49 01 d0 48 ba 00 0b 27 69 fe 98 d6 a6 48 01 c2 48 b8 b1 bd 16 f4 de 18 02 00 4c 11 c0 49 89 c0 49 0f ac d0 06 48 0f a4 d0 3a 31 ed 48 ba 59 38 49 f3 c7 b4 36 8d 48 39 d0 48 b8 ed b5 a0 f7 c6 10 00 00 49 19 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GlassWorm_DA_2147968075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GlassWorm.DA!MTB"
        threat_id = "2147968075"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GlassWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC" ascii //weight: 20
        $x_5_2 = "n4vZvghsGj9KCE8AJVtbc9S8o8SC" ascii //weight: 5
        $x_5_3 = "CE8AJVtbc9S8o8SC" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

