rule Trojan_Win64_Blister_A_2147813778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Blister.A"
        threat_id = "2147813778"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Blister"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {65 48 8b 04 25 60 00 00 00 44 0f b7 db 48 8b 48 18 48 8b 41 30}  //weight: 4, accuracy: High
        $x_4_2 = {41 8b 0a 8b d3 49 03 ?? 8a 01 84 c0}  //weight: 4, accuracy: Low
        $x_4_3 = {c1 c2 09 0f be c0 03 d0 8a 01 84 c0}  //weight: 4, accuracy: High
        $x_4_4 = {48 8b c3 49 03 ?? 83 e0 03 8a 44 ?? ?? 41 30 ?? 4d 03}  //weight: 4, accuracy: Low
        $x_4_5 = {ff d6 48 8d 87 ?? ?? 00 00 48 8d [0-3] ff d0}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win64_Blister_B_2147839543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Blister.B"
        threat_id = "2147839543"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Blister"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 38 19 c1 aa f6 e9 00 00 00 00}  //weight: 5, accuracy: High
        $x_5_2 = {3d 4d 5a 00 00 e9 00 00 00 00}  //weight: 5, accuracy: High
        $x_5_3 = {e9 00 00 00 00 ff d0}  //weight: 5, accuracy: High
        $x_5_4 = {57 00 49 00 c7 44 ?? ?? 4e 00 44 00 c7 44 ?? ?? 49 00 52 00}  //weight: 5, accuracy: Low
        $x_5_5 = {57 00 65 00 [0-16] 72 00 46 00 [0-16] 61 00 75 00 [0-25] 6c 00 74 00 09 00 ff d0}  //weight: 5, accuracy: Low
        $x_1_6 = {e9 00 00 00 00 c6 84}  //weight: 1, accuracy: High
        $x_1_7 = {e9 01 00 00 00 ?? c6 84}  //weight: 1, accuracy: Low
        $x_1_8 = {e9 03 00 00 00 ?? ?? ?? c6 84}  //weight: 1, accuracy: Low
        $x_1_9 = {e9 04 00 00 00 ?? ?? ?? ?? c6 84}  //weight: 1, accuracy: Low
        $x_1_10 = {e9 06 00 00 00 ?? ?? ?? ?? ?? ?? c6 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 3 of ($x_1_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Blister_AC_2147888183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Blister.AC!MTB"
        threat_id = "2147888183"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Blister"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 17 83 e3 07 48 83 c7 04 8b ca 8b c2 41 23 cb 41 0b c3 f7 d1 23 c8 41 2b c8 44 8b c2 89 0e 8b cb 48 83 c6 04 41 d3 c0 ff c3 49 83 e9 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Blister_MA_2147895633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Blister.MA!MTB"
        threat_id = "2147895633"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Blister"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 03 ca 4d 63 d0 41 80 d2 10 49 0b fe 44 8b 51 20 40 d2 de 49 c1 c0 38 66 c1 ee 04 8b 79 1c 66 41 c1 f0 9f 4d 8d 14 12 40 d2 c6 44 8b 41 24 40 80 e6 5d 48 03 fa 40 c0 d6 c9 48 d3 fe 8b 71 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

