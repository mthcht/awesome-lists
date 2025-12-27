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

