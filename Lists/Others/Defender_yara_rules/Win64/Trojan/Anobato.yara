rule Trojan_Win64_Anobato_A_2147708151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Anobato.A"
        threat_id = "2147708151"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Anobato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 08 48 83 ec 20 eb 0a 6e 74 64 6c 6c 2e 64 6c 6c 00 48 8d 0d ef ff ff ff ff 15 ?? ?? ?? ?? 48 83 c4 20}  //weight: 1, accuracy: Low
        $x_1_2 = {48 05 04 d0 07 00 48 81 be b0 01 00 00 0c 0c 0c 0c 75 09}  //weight: 1, accuracy: High
        $x_2_3 = "regsvrmobsynrundllrunonc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Anobato_A_2147708151_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Anobato.A"
        threat_id = "2147708151"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Anobato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 08 81 38 55 48 89 e5 74 0c 48 83 fb 00 75 06 31 08 ff c1 eb ea}  //weight: 1, accuracy: High
        $x_1_2 = {48 83 ec 20 48 c7 c1 00 00 00 00 48 c7 c2 00 80 02 00 49 c7 c0 00 30 00 00 49 c7 c1 40 00 00 00 ff 15 ?? ?? ?? ?? 48 83 c4 20 48 83 f8 00 75 02 eb ce}  //weight: 1, accuracy: Low
        $x_1_3 = {81 fb 04 04 00 00 73 09 48 83 c0 04 83 c3 04 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Anobato_A_2147708151_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Anobato.A"
        threat_id = "2147708151"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Anobato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 20 eb 0d 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 48 8d 0d ec ff ff ff ff 15 ?? ?? ?? ?? 48 83 c4 20 90}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 ec 20 48 c7 c1 00 00 00 00 48 c7 c2 00 14 00 00 49 c7 c0 00 30 00 00 49 c7 c1 04 00 00 00 ff d0}  //weight: 1, accuracy: High
        $x_1_3 = {eb 06 38 35 2e 39 33 00}  //weight: 1, accuracy: High
        $x_1_4 = {eb 06 2e 30 2e 32 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Anobato_A_2147708151_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Anobato.A"
        threat_id = "2147708151"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Anobato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b 0f 67 8b 49 04 41 8b 17 01 da 83 c2 0c 67 31 0a 41 3b 87 ?? ?? 00 00 73 08 83 c0 04 83 c3 04 eb e4}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b 1f 8b 43 08 83 f8 00 74 07 80 7c 03 ff c3 74 02 eb 26}  //weight: 1, accuracy: High
        $x_1_3 = {00 64 48 83 ec 20 48 c7 c1 00 00 00 00 48 c7 c2 00 40 01 00 49 c7 c0 00 30 00 00 49 c7 c1 40 00 00 00 41 ff}  //weight: 1, accuracy: High
        $x_1_4 = {eb 0f 31 39 33 2e 32 38 2e 31 37 39 2e 31 30 35 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

