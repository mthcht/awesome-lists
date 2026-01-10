rule Trojan_Win32_SilverBaron_A_2147960925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SilverBaron.A"
        threat_id = "2147960925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SilverBaron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 59 53 54 45 4d 5f 49 4e 46 4f 7c 43 6f 6d 70 75 74 65 72 3a 25 73 7c 44 6f 6d 61 69 6e 3a 25 73 7c 55 73 65 72 3a 25 73 7c 42 75 69 6c 64 3a 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 45 41 52 54 42 45 41 54 5f 52 45 53 50 4f 4e 53 45 00}  //weight: 1, accuracy: High
        $x_1_3 = {54 41 4b 45 5f 53 43 52 45 45 4e 53 48 4f 54 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 4f 57 4e 4c 4f 41 44 3a 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 63 72 65 65 6e 73 68 6f 74 5f 25 30 34 64 25 30 32 64 25 30 32 64 5f 25 30 32 64 25 30 32 64 25 30 32 64 2e 62 6d 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

