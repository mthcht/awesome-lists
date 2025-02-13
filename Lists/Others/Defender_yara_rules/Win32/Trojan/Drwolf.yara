rule Trojan_Win32_Drwolf_A_2147631243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drwolf.A"
        threat_id = "2147631243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drwolf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 59 53 54 45 4d 72 4f 4f 54 25 5c 73 59 53 54 45 4d 33 32 5c 53 76 43 48 6f 53 74 2e 45 78 45 20 2d 4b 20 4e 45 54 53 56 43 53 00 00 00 00 52 65 67 53 65 74 56 61 6c 75 65 45 78 28 53 65 72 76 69 63 65 44 6c 6c 29}  //weight: 1, accuracy: High
        $x_1_2 = {73 25 5c 73 65 63 69 76 72 65 73 5c 74 65 73 6c 6f 72 74 6e 6f 63 74 6e 65 72 72 75 63 5c 6d 65 74 73 79 73 00 00 00 00 5c 69 6e 73 74 61 6c 6c 2e 74 6d 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

