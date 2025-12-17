rule Trojan_Win64_GhostRat_LML_2147932821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GhostRat.LML!MTB"
        threat_id = "2147932821"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 54 11 01 80 30 a7 48 83 c0 01 48 39 d0 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GhostRat_NG_2147933092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GhostRat.NG!MTB"
        threat_id = "2147933092"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 b8 4d 00 00 00 41 b9 4c 00 00 00 e8 bc fc ff ff 48 8d 0d 2d e8 20 00 41 b8 08 00 00 00 41 b9 5a 00 00 00 e8 a4 fc ff ff 48 8d 0d c6 e7 20 00 41 b8 5e 00 00 00 45 31 c9 e8 8f fc ff ff}  //weight: 2, accuracy: High
        $x_1_2 = {88 86 04 01 00 00 e8 23 d9 17 00 48 63 c8 48 89 c8 48 d1 e8 48 f7 e7 48 c1 ea 04 48 89 d0 48 c1 e0 06 48 01 d2 48 29 c2 48 01 ca 0f b6 04 13 88 86 05 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "buatle.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GhostRat_DCP_2147935876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GhostRat.DCP!MTB"
        threat_id = "2147935876"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 8a 24 11 c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff d8 c5 cd 60 e1 c5 cd 68 f1 c5 c5 60 c1 c5 c5 68 f9 44 30 24 0f c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd c5 c5 73 d8 02 c5 fd 69 f4 c5 fd 61 c4 c5 dd 73 dc 02 c5 f5 73 db 02 c5 e5 69 d7 48 ff c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GhostRat_AGO_2147942563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GhostRat.AGO!MTB"
        threat_id = "2147942563"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 10 32 45 d7 8b 55 fc 48 63 d2 48 8d 0d ?? ?? ?? ?? 88 04 0a 83 45 fc 01 8b 55 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GhostRat_HB_2147952088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GhostRat.HB!MTB"
        threat_id = "2147952088"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "IpDates_info" wide //weight: 6
        $x_10_2 = "%s-%04d%02d%02d-%02d%02d%02d.dmp" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

