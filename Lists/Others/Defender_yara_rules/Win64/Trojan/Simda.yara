rule Trojan_Win64_Simda_A_2147650741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Simda.A"
        threat_id = "2147650741"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Simda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 01 49 ff c0 32 c2 80 c2 0d 0f b6 c0 66 89 01 48 8b 03 4a 8d 0c 40}  //weight: 1, accuracy: High
        $x_1_2 = {66 83 38 4f 75 19 66 83 78 02 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Simda_B_2147650742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Simda.B"
        threat_id = "2147650742"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Simda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 41 01 32 01 48 83 c1 02 88 02}  //weight: 1, accuracy: High
        $x_1_2 = {c7 42 2c 57 00 00 00 b8 34 00 00 00 33 ed c6 42 28 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Simda_EB_2147838536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Simda.EB!MTB"
        threat_id = "2147838536"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {4c 21 5d 80 49 c7 c1 ea d0 00 00 49 81 c1 87 8c 00 00 4d 89 de 4d 89 e1 4d 11 ce 67 41 81 2f a9 87 70 5f 4c 8b 4d e8}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

