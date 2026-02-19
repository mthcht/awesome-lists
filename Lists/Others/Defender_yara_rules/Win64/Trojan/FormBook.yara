rule Trojan_Win64_FormBook_ABF_2147901016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FormBook.ABF!MTB"
        threat_id = "2147901016"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8d 05 f9 16 45 00 48 8d 15 e2 64 3a 00 48 8d 0d 03 65 3a 00 e8 ?? ?? ?? ?? 4c 8d 05 9f 57 44 00 33 d2 48 8d 0d 0e 65 3a 00 e8 ?? ?? ?? ?? 4c 8d 05 da 16 45 00 48 8d 15 1b 65 3a 00 48 8d 0d 7c 66 3a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FormBook_AFK_2147911695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FormBook.AFK!MTB"
        threat_id = "2147911695"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 8b c1 41 c1 f8 1f 41 83 e0 0f 44 03 c1 41 83 e0 f0 44 8b c9 45 2b c8 45 8b c1 46 0f b7 44 46 0c 41 33 d0 44 8b c1 66 42 89 54 40 10 ff c1 83 f9 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FormBook_BSA_2147941901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FormBook.BSA!MTB"
        threat_id = "2147941901"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aYF5jO6I7xTpy9h9O0cOUGnLv2.dll" ascii //weight: 1
        $x_1_2 = "0MxRU53g7cTT9JjSuFiR6x5FUh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FormBook_GVA_2147952371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FormBook.GVA!MTB"
        threat_id = "2147952371"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 4d 8d 54 00 10 4c 8b 8d ?? ?? ?? ?? 8b c1 99 41 f7 79 08 41 3b 51 08 73 16 8b c2 41 0f b6 44 01 10 41 30 02 ff c1 41 39 4c 24 08 7f d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FormBook_NH_2147960330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FormBook.NH!MTB"
        threat_id = "2147960330"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 4c 24 58 48 89 08 48 8b 4c 24 60 48 89 48 08 8b 4c 24 68 89 c9 48 89 48 10 8b 4c 24 6c 89 c9 48 89 48 18 48 89 c3 b9 04 00 00 00 48 89 cf 48 8b 44 24 30}  //weight: 2, accuracy: High
        $x_1_2 = {48 8b 44 24 20 48 85 c0 bb 00 00 00 00 48 8b 4c 24 28 48 0f 44 d9 b9 00 00 00 00 48 8b 54 24 40 48 0f 44 ca 48 8b 6c 24 48 48 83 c4 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FormBook_AKK_2147962914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FormBook.AKK!MTB"
        threat_id = "2147962914"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8d 05 b8 f9 02 00 48 8d 54 24 20 0f 10 00 0f 11 05 c9 86 03 00 e8 ?? ?? ?? ?? 4c 8d 05 ad f9 02 00 48 8d 54 24 20 0f 10 00 0f 11 05 1e 87 03 00 e8 ?? ?? ?? ?? 4c 8d 05 aa f9 02 00 48 8d 54 24 20 0f 10 00 0f 11 05 c3 86 03 00 e8 ?? ?? ?? ?? 4c 8d 05 a7 f9 02 00 48 8d 54 24 20 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FormBook_AOO_2147963084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FormBook.AOO!MTB"
        threat_id = "2147963084"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 4d a0 32 4c 15 b8 88 4c 15 e8 48 ff c2 48 83 fa 10}  //weight: 2, accuracy: High
        $x_3_2 = {66 03 ff 66 46 89 0c 30 66 46 89 44 30 02 8d 57 02 0f b7 45 af 4e 89 14 30 0f b7 45 b1 66 42 89 3c 30 66 42 89 54 30 02 0f b7 45 b3 4a 89 1c 30 49 8b 04 37 49 8b 0c 04}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FormBook_AFH_2147963376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FormBook.AFH!MTB"
        threat_id = "2147963376"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 da 0f b6 45 e7 34 28 88 45 db 0f b6 45 e7 34 3f 88 45 dc 0f b6 45 e7 34 3b 88 45 dd 0f b6 45 e7 34 3e 88 45 de 0f b6 45 e7 34 5a 88 45 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

