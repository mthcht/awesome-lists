rule Trojan_Win32_Offcrypt_A_2147607882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Offcrypt.A"
        threat_id = "2147607882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Offcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 6c 00 6f 00 73 00 65 00 00 00 53 00 61 00 76 00 65 00 41 00 73 00 00 00 00 00 41 00 63 00 74 00 69 00 76 00 65 00 57 00 6f 00 72 00 6b 00 62 00 6f 00 6f 00 6b 00 00 00 00 00 4f 00 70 00 65 00 6e 00 00 00 00 00 74 00 74 00 71 00 00 00 41 00 63 00 74 00 69 00 76 00 65 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 00 00 00 00 44 00 69 00 73 00 70 00 6c 00 61 00 79 00 41 00 6c 00 65 00 72 00 74 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "Word.Application" wide //weight: 1
        $x_1_3 = "Excel.Application" wide //weight: 1
        $x_1_4 = {54 58 4f 53 65 72 76 69 63 65 00 00 5c 45 78 65 63 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

