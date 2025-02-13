rule Trojan_Win32_Keyjack_A_2147621514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Keyjack.A"
        threat_id = "2147621514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Keyjack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 73 6e 2e 63 6f 6d [0-4] 61 6f 6c 2e 63 6f 6d [0-4] 79 61 68 6f 6f 2e 63 6f 6d [0-4] 67 6f 6f 67 6c 65 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_2 = "%S?p=%u&q=&i=%u" wide //weight: 1
        $x_1_3 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e [0-6] 6b 65 79 77 6f 72 64 73}  //weight: 1, accuracy: Low
        $x_1_4 = {52 53 31 2f 49 6e 73 74 61 6c 6c 65 64 42 75 6e 64 6c 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

