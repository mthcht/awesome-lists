rule Backdoor_Win32_Brambul_A_2147629314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Brambul.A"
        threat_id = "2147629314"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Brambul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 ba 00 00 00 66 c7 44 24 04 02 00 c7 44 24 08 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 ff 75 08 c7 44 24 18 34 42 4d 53 8b 4c 24 18 81 e9 31 42 4d 53}  //weight: 1, accuracy: High
        $x_1_3 = {b3 63 bf 01 00 00 00 c6 44 24 0d 3a c6 44 24 0e 5c}  //weight: 1, accuracy: High
        $x_1_4 = {ff d6 48 83 f8 05 77 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

