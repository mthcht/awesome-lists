rule Trojan_Win32_Hala_B_2147595123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hala.B"
        threat_id = "2147595123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hala"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 65 e8 33 f6 89 75 e4 56 56 6a 03 56 56 68 00 00 00 80}  //weight: 1, accuracy: High
        $x_1_2 = {5c 47 6f 6f 67 6c 65 00 53 6f 66 74 77 61 72 65}  //weight: 1, accuracy: High
        $x_1_3 = {67 6f 6e 72 61 6a 61 2e 65 78 65 00 00 6d 68 63}  //weight: 1, accuracy: High
        $x_1_4 = {63 61 62 61 6c 2e 65 78 65 00 00 00 63 61 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

