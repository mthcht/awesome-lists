rule Trojan_Win32_PsAttack_D_2147729885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsAttack.D"
        threat_id = "2147729885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsAttack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 6d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 2e 00 61 00 75 00 74 00 6f 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 73 00 63 00 72 00 69 00 70 00 74 00 62 00 6c 00 6f 00 63 00 6b 00 00 [0-16] 77 00 72 00 69 00 74 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 62 00 6c 00 6f 00 63 00 6b 00 74 00 6f 00 6c 00 6f 00 67 00 00 [0-16] 6c 00 6f 00 67 00 73 00 63 00 72 00 69 00 70 00 74 00 62 00 6c 00 6f 00 63 00 6b 00 73 00 74 00 61 00 72 00 74 00 00 [0-16] 6c 00 6f 00 67 00 73 00 63 00 72 00 69 00 70 00 74 00 62 00 6c 00 6f 00 63 00 6b 00 65 00 6e 00 64 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {73 79 73 74 65 6d 2e 6d 61 6e 61 67 65 6d 65 6e 74 2e 61 75 74 6f 6d 61 74 69 6f 6e 2e 73 63 72 69 70 74 62 6c 6f 63 6b 00 [0-16] 77 72 69 74 65 73 63 72 69 70 74 62 6c 6f 63 6b 74 6f 6c 6f 67 00 [0-16] 6c 6f 67 73 63 72 69 70 74 62 6c 6f 63 6b 73 74 61 72 74 00 [0-16] 6c 6f 67 73 63 72 69 70 74 62 6c 6f 63 6b 65 6e 64 00}  //weight: 1, accuracy: Low
        $x_1_3 = {53 79 73 74 65 6d 2e 4d 61 6e 61 67 65 6d 65 6e 74 2e 41 75 74 6f 6d 61 74 69 6f 6e 2e 41 6d 73 69 55 74 69 6c 73 00}  //weight: 1, accuracy: High
        $x_2_4 = {77 00 72 00 69 00 74 00 65 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 65 00 76 00 65 00 6e 00 74 00 00 [0-16] 69 6e 76 69 73 69 73 68 65 6c 6c 70 72 6f 66 69 6c 65 72 2e 64 6c 6c 00}  //weight: 2, accuracy: Low
        $x_2_5 = {49 6e 76 69 73 69 53 68 65 6c 6c 50 72 6f 66 69 6c 65 72 2e 44 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

