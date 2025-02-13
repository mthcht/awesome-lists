rule Trojan_Win32_Cueisfry_A_2147685131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cueisfry.A"
        threat_id = "2147685131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cueisfry"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 30 80 c1 7a 80 f1 17 88 0c 30 40 3b c2 7c ef}  //weight: 1, accuracy: High
        $x_1_2 = "?verify=" ascii //weight: 1
        $x_1_3 = {63 73 72 73 73 77 69 6e 6c 6f 67 6f 6e 73 65 72 76 69 63 65 73 6c 73 61 73 73 73 76 63 68 6f 73 74 73 70 6f 6f 6c 73 76 65 78 70 6c 6f 72 65 72 63 74 66 6d 6f 6e 63 6f 6e 69 6d 65 77 6d 69 70 72 76 73 65 73 79 73 74 65 6d 73 6d 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

