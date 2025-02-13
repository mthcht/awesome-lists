rule Trojan_Win32_Korpode_A_2147725782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Korpode.A!dha"
        threat_id = "2147725782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Korpode"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 00 70 00 68 00 6f 00 5f 00 25 00 73 00 5f 00 25 00 64 00 2e 00 6a 00 70 00 67 00 00 00 00 00 6b 00 69 00 6c 00 6c 00 00 00 00 00 70 00 75 00 62 00 00 00 73 00 64 00 61 00 00 00 77 00 55 00 42 00 74 00 5a 00 4c 00 70 00 4b 00 35 00 6a 00 58 00 6a 00 31 00 45 00 6d 00 52 00 5a 00 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 00 65 00 66 00 5f 00 25 00 73 00 2e 00 6a 00 70 00 67 00 00 00 62 00 62 00 00 00 00 00 61 00 61 00 00 00 00 00 2f 00 41 00 44 00 49 00 2e 00 62 00 69 00 6e 00 00 00 00 00 2f 00 44 00 44 00 49 00 2e 00 62 00 69 00 6e 00 00 00 00 00 2f 00 41 00 44 00 58 00 2e 00 65 00 6e 00 63 00 00 00 00 00 2f 00 44 00 44 00 58 00 2e 00 65 00 6e 00 63 00 00 00 00 00 2f 00 45 00 52 00 53 00 50 00}  //weight: 1, accuracy: High
        $x_1_3 = {74 61 62 6c 65 29 00 00 28 4c 61 70 74 6f 70 29 00 00 00 00 28 4e 6f 74 65 62 6f 6f 6b 29 00 00 28 53 75 62 20 4e 6f 74 65 62 6f 6f 6b 29 00 00 25 73 20 00 5c 00 00 00 25 64 2e 25 64 2e 25 64 2e 25 64 00 25 30 34 58 25 30 34 58 00 00 00 00 53 62 69 65 44 6c 6c 2e 64 6c 6c 00 64 62 67 68 65 6c 70 2e 64 6c 6c 00 61 70 69 5f 6c 6f 67 2e}  //weight: 1, accuracy: High
        $x_1_4 = {5c 54 2b 4d 5c 52 65 73 75 6c 74 5c 44 6f 63 50 72 69 6e 74 2e 70 64 62 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

