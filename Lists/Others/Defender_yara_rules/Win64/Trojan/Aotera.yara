rule Trojan_Win64_Aotera_KK_2147962258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Aotera.KK!MTB"
        threat_id = "2147962258"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Aotera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8b d1 41 8b 54 96 10 43 89 54 8e 10 8b d1 45 89 5c 96 10 41 ff c1 41 81 f9 00 01 00 00}  //weight: 20, accuracy: High
        $x_10_2 = {41 8b c3 41 0f b6 44 86 10 33 d0 41 8b c1 88 54 01 10 41 ff c1 41 3b f9}  //weight: 10, accuracy: High
        $x_5_3 = {41 c1 e7 04 41 0b c7 42 88 44 37 10 83 c5 02 41 ff c6 3b ee 7c c0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Aotera_GVF_2147962303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Aotera.GVF!MTB"
        threat_id = "2147962303"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Aotera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 4e d0 8b c1 f7 d8 44 8b c0 41 83 c8 01 45 0f bd d0 f3 45 0f bd c0 41 83 f0 1f f7 05 8a 5e 11 00 00 10 00 00 45 0f 45 d0 45 8b c2 49 c1 e0 03 4c 8d 15 80 7b 0d 00 4d 03 c2 49 03 00 48 c1 f8 20 3b d0 0f 4d c2 03 c6 41 3b 41 08 0f 8f f9 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "gSXHUr3OcH98GNkXZyjGlRa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Aotera_KKA_2147962593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Aotera.KKA!MTB"
        threat_id = "2147962593"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Aotera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8b c1 44 0f b6 44 06 10 41 83 f0 42 44 88 44 06 10 ff c1 3b d1}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Aotera_RR_2147962990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Aotera.RR!MTB"
        threat_id = "2147962990"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Aotera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 33 18 45 89 18 45 8b c3 41 c1 e0 0c 41 c1 eb 14 45 0b c3 45 8b c8 44 89 09 44 03 02 44 89 02 48 8b d0 44 33 02 44 89 02 41 8b d0 c1 e2 08 41 c1 e8 18 41 0b d0 44 8b c2 44 89 00 41 03 12 41 89 12 48 8b c1 33 10 89 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Aotera_AH_2147963108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Aotera.AH!MTB"
        threat_id = "2147963108"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Aotera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "fwI5CYY8elcXi9rOF3iD4stGKMMZe0BstM8GZDIO3xWgXICM8R5XqXHuJYw" ascii //weight: 10
        $x_20_2 = "fgUgHIQ7f1AezJfhCkfW89FNBMwbNFRup5scYzkywRmsXZbftA5dpW+0Ys21wE7" ascii //weight: 20
        $x_30_3 = "ew0jE8ckfkwcjZ6gEUyF8tRaBY0WehJgud4dfz08wR/jSp+atAYYqnWvew=" ascii //weight: 30
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

