rule Trojan_Win64_EggStremeLoader_C_2147952130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EggStremeLoader.C!MTB"
        threat_id = "2147952130"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 63 ca 8a 04 31 41 88 04 30 44 88 0c 31 41 0f b6 0c 30 49 03 c9 0f b6 c1 8a 0c 30 41 30 0c 24 4d 03 e3 4d 2b d3 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EggStremeLoader_CA_2147952134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EggStremeLoader.CA!MTB"
        threat_id = "2147952134"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c9 48 8d 05 ?? ?? ?? ?? 8a 04 01 34 dd 88 84 0d ?? ?? ?? ?? 48 ff c1 48 83 f9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EggStremeLoader_G_2147954810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EggStremeLoader.G!dha"
        threat_id = "2147954810"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 c7 41 0a 48 ba [0-16] 66 c7 41 14 41 b8 [0-16] 66 c7 41 1a 49 b9}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 41 29 48 83 ec 20 [0-16] 66 c7 41 2d 48 b8 [0-16] 66 c7 41 37 ff d0}  //weight: 1, accuracy: Low
        $x_2_3 = {b9 48 b9 00 00 66 89 8c 24 c0 00 00 00 [0-16] b9 48 ba 00 00 [0-24] b8 41 b8 00 00 [0-24] b8 49 b9 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

