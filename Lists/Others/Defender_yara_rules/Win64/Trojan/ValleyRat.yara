rule Trojan_Win64_ValleyRat_ASD_2147929877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.ASD!MTB"
        threat_id = "2147929877"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {2b c8 b8 cd cc cc cc 41 f7 e2 80 c1 36 49 8d 43 01 41 30 4c 38 ff 45 33 db c1 ea 03 41 ff c2 8d 0c 92 03 c9 44 3b c9 4c 0f 45 d8}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_CZ_2147940457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.CZ!MTB"
        threat_id = "2147940457"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 8b c8 33 d2 49 8b c1 49 f7 70 10 8a 04 0a 43 30 04 19 49 ff c1 4d 3b ca 72 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_RY_2147942017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.RY!MTB"
        threat_id = "2147942017"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 0f 48 63 6c 24 ?? 48 69 dd ?? ?? ?? ?? 48 89 de 48 c1 ee ?? 48 c1 eb 20 01 f3 01 db 8d 1c 5b 29 dd 48 63 ed 32 94 2c ?? ?? ?? ?? 88 14 0f 8b 4c 24 ?? 83 c1 01 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_ETL_2147944051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.ETL!MTB"
        threat_id = "2147944051"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b c0 4d 8d 49 01 99 41 ff c0 f7 f9 48 63 c2 0f b6 44 04 38 43 32 44 11 ff 42 88 84 0c 1f 05 00 00 41 81 f8 d8 08 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

