rule Trojan_Win32_Brackash_A_2147602713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Brackash.gen!A"
        threat_id = "2147602713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Brackash"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 0d 53 56 68 f4 05 00 00 50 e8 ?? ?? ff ff a1}  //weight: 10, accuracy: Low
        $x_7_2 = {50 6a 0a e8 ?? ?? ff ff a3 ?? ?? ?? ?? c3}  //weight: 7, accuracy: Low
        $x_6_3 = {53 68 65 6c 6c 45 76 65 6e 74 2e 64 6c 6c 00 48 6b 4f 66 66 00 48 6b 4f 6e 00}  //weight: 6, accuracy: High
        $x_6_4 = {72 61 6e 64 6f 6d 66 75 6e 63 69 6f 6e 64 69 72 6d 65 6d 6f 72 79 68 61 74 65 00}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_6_*))) or
            ((1 of ($x_7_*) and 1 of ($x_6_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Brackash_B_2147602714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Brackash.gen!B"
        threat_id = "2147602714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Brackash"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e8 06 00 00 00 8b 75 08 c6 45 e2 68 c6 45 e7 c3 c6 45 ff 00 33 c0}  //weight: 1, accuracy: High
        $x_1_2 = {74 35 8b 01 33 d2 52 50 a1 ?? ?? ?? ?? 99 3b 54 24 04 75 03 3b 04 24 5a 58 75 07 b8 05 00 00 00 eb 28 51 8b 45 10 50 8b 45 0c 50 8b 45 08 50 ff 15 ?? ?? ?? ?? eb 13 51 8b 45 10 50 8b 45 0c 50 8b 45 08 50 ff 15 ?? ?? ?? ?? 5d c2}  //weight: 1, accuracy: Low
        $x_1_3 = {74 49 8b 45 f4 50 8d 45 f0 50 e8 ?? ?? ff ff 8b 45 f0 50 8d 45 e4 e8 ?? ?? ff ff 8b 45 e4 8d 55 e8 e8 ?? ?? ff ff 8d 45 e8 ba ?? ?? ?? ?? e8 ?? ?? ff ff 8b 45 e8 50 8d 45 ec 50 e8 ?? ?? ff ff 8b 55 ec 58 e8 ?? ?? ff ff 75 16}  //weight: 1, accuracy: Low
        $x_1_4 = {89 45 fc 83 fb 05 (0f 85 a2 00|75 51) 83 7d fc 00 (0f 85 98 00|75 4b) 33 f6 8d 1c 37 8d 55 f4 8b 43 3c e8 ?? ?? ff ff 8b 43 44 33 d2 52 50 a1 ?? ?? ?? ?? 99 3b 54 24 04 75 03 3b 04 24 5a 58}  //weight: 1, accuracy: Low
        $x_1_5 = {72 61 6e 64 6f 6d 66 75 6e 63 69 6f 6e 64 69 72 6d 65 6d 6f 72 79 6c 69 6b 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Brackash_A_2147608441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Brackash.A"
        threat_id = "2147608441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Brackash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 65 6d 6f 72 79 [0-12] 6c 69 6b 65 [0-12] 6c 6f 76 65}  //weight: 1, accuracy: Low
        $x_1_2 = {74 61 73 6b [0-4] ff ff ff ff 05 00 00 00 69 65 78 70 6c [0-4] ff ff ff ff 03 00 00 00 6d 67 72 [0-4] ff ff ff ff 03 00 00 00 6f 72 65 [0-4] ff ff ff ff 04 00 00 00 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {74 0d 53 56 68 f4 05 00 00 50 e8 ?? ?? ff ff a1}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff 8b 06 e8 ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Brackash_C_2147609191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Brackash.gen!C"
        threat_id = "2147609191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Brackash"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 0d 53 56 68 f4 05 00 00 50 e8 ?? ?? ff ff a1}  //weight: 10, accuracy: Low
        $x_7_2 = {50 6a 0a e8 ?? ?? ff ff a3}  //weight: 7, accuracy: Low
        $x_1_3 = "memory" ascii //weight: 1
        $x_1_4 = "random" ascii //weight: 1
        $x_1_5 = "bboy" ascii //weight: 1
        $x_1_6 = "beauty" ascii //weight: 1
        $x_1_7 = "group" ascii //weight: 1
        $x_1_8 = "funcion" ascii //weight: 1
        $x_1_9 = "bobae" ascii //weight: 1
        $x_1_10 = "hate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

