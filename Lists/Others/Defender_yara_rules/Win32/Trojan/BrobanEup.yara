rule Trojan_Win32_BrobanEup_A_2147690447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BrobanEup.A"
        threat_id = "2147690447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanEup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3b e9 75 0c 83 fe 05 72 07 8b c7 2b c3 01 43 01 8b cf 2b cb 83 e9 05 c6 04 1e e9 89 4c 1e 01}  //weight: 1, accuracy: High
        $x_1_2 = {8b 03 3d 48 45 41 44 74 ?? 3d 50 4f 53 54 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BrobanEup_A_2147690447_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BrobanEup.A"
        threat_id = "2147690447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanEup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 6a 01 ff 74 24 0c b8 44 33 22 11 ff d0 c3}  //weight: 10, accuracy: High
        $x_1_2 = {8b 4e 28 03 4d ?? 53 6a 11 68 ?? ?? ?? ?? 50 ff 75 08 89 0d ?? ?? ?? ?? ff d7}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4f 28 03 4d ?? 53 6a 11 68 ?? ?? ?? ?? 50 ff 75 08 89 0d ?? ?? ?? ?? ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BrobanEup_A_2147690447_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BrobanEup.A"
        threat_id = "2147690447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanEup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/eupds.php" ascii //weight: 1
        $x_1_2 = "</bolahtml>" ascii //weight: 1
        $x_1_3 = "pagador.com.br" ascii //weight: 1
        $x_1_4 = "/index1.php?log=" ascii //weight: 1
        $x_1_5 = "[gforce_dll]:" ascii //weight: 1
        $x_1_6 = "boleto" ascii //weight: 1
        $x_1_7 = "segundavia" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_BrobanEup_A_2147690447_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BrobanEup.A"
        threat_id = "2147690447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanEup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 67 00 00 3e 3c 00 00 4d 47 00 00 3c 2f 62 69 67 6e 75 6d 62 6f 6c 61 3e 00 00 00 3c 62 69 67 6e 75 6d 62 6f 6c 61 3e 00}  //weight: 1, accuracy: High
        $x_1_2 = {3c 62 6f 6c 61 68 74 6d 6c 3e 00 00 3c 66 69 6e 61 6c 3e 3c 2f 66 69 6e 61 6c 3e 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 62 6d 70 00 00 00 00 2e 66 6c 76 00 00 00 00 2e 73 77 66 00 00 00 00 2e 70 6e 67 00 00 00 00 2e 6a 70 65 67 00 00 00 2e 6a 70 67 00 00 00 00 2e 67 69 66 00}  //weight: 1, accuracy: High
        $x_1_4 = {78 79 7a 30 31 32 33 34 35 36 37 38 39 2d 5f 00}  //weight: 1, accuracy: High
        $x_1_5 = {26 63 6f 6e 66 69 67 3d 7b 00 00 00 61 64 65 72 26 63 6f 64 00 00 00 00 47 45 54 00 48 54 54 50}  //weight: 1, accuracy: High
        $x_1_6 = {75 73 65 72 69 6e 69 74 2e 65 78 65 00 00 00 00 53 79 73 74 65 6d 20 49 64 6c 65 20 50 72 6f 63 65 73 73 00 53 79 73 74 65 6d 00 00 49 6e 74 65 72 72 75 70 74 73 00 00 63 73 72 73 73 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_7 = {40 a3 04 10 01 00 80 3c 08 55 75 f4 80 7c 08 01 8b 75 ed 80 7c 08 02 ec 75 e6 80 7c 08 03 8b 75 df 80 7c 08 04 4d 75 d8 80 7c 08 05 08 75 d1 80 7c 08 06 56 75 ca 80 7c 08 07 8b}  //weight: 1, accuracy: High
        $x_1_8 = {8b 02 3d 34 30 39 2d 0f 84 3d 01 00 00 3d 33 34 31 2d 0f 84 32 01 00 00 3d 36 35 32 2d 0f 84 27 01 00 00 3d 33 39 39 2d 0f 84 1c 01 00 00 3d 34 37 37 2d 0f 84 11 01 00 00 3d 31 30 34 2d 0f 84 06 01 00 00 3d 30 37 30 2d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

