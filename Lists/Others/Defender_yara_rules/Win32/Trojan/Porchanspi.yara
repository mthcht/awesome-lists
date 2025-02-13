rule Trojan_Win32_Porchanspi_A_2147662936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Porchanspi.A"
        threat_id = "2147662936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Porchanspi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 6e 74 69 43 68 69 6c 64 20 50 6f 72 6e 6f 20 53 70 61 6d 20 50 72 6f 74 65 63 74 69 6f 6e 00}  //weight: 2, accuracy: High
        $x_1_2 = {59 6f 75 72 20 49 44 20 4e 75 6d 62 65 72 20 61 6e 64 20 6f 75 72 20 63 6f 6e 74 61 63 74 73 20 28 70 6c 65 61 73 65 20 77 72 69 74 65 20 64 6f 77 6e 20 74 68 69 73 20 64 61 74 61 29 3a 00}  //weight: 1, accuracy: High
        $x_1_3 = {40 67 6d 61 69 6c 2e 63 6f 6d 00 09 00 73 65 63 06 00}  //weight: 1, accuracy: Low
        $x_1_4 = {20 4f 75 72 20 73 70 65 63 69 61 6c 20 73 65 72 76 69 63 65 20 65 6d 61 69 6c 3a 20 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 73 76 63 66 6e 6d 61 69 6e 73 74 76 65 73 74 76 73 5c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Porchanspi_B_2147670475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Porchanspi.B"
        threat_id = "2147670475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Porchanspi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Anti-Child Porn Spam Protection (18 U.S.C. " ascii //weight: 5
        $x_2_2 = "Wrong code!" ascii //weight: 2
        $x_5_3 = "Your Id #:  Our special service email: security11220@gmail.com" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

