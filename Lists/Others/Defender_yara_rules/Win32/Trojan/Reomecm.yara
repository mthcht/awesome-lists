rule Trojan_Win32_Reomecm_A_2147955114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reomecm.A"
        threat_id = "2147955114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reomecm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 65 78 70 2e 64 6c 6c 00 52 65 64 69 73 4d 6f 64 75 6c 65 5f 4f 6e 4c 6f 61 64}  //weight: 10, accuracy: High
        $x_10_2 = {72 00 00 00 7b 00 00 00 7d 00 00 00 73 79 73 74 65 6d 00 00 00 00 00 00 72 65 61 64 6f 6e 6c 79}  //weight: 10, accuracy: High
        $x_5_3 = "RedisModule_CreateCommand" ascii //weight: 5
        $x_5_4 = {00 73 79 73 74 65 6d 2e 65 78 65 63 00}  //weight: 5, accuracy: High
        $x_1_5 = {66 67 65 74 73 [0-16] 5f 70 6f 70 65 6e [0-16] 6d 61 6c 6c 6f 63 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 65 64 69 73 4d 6f 64 75 6c 65 5f 43 72 65 61 74 65 53 74 72 69 6e 67 [0-16] 52 65 64 69 73 4d 6f 64 75 6c 65 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

