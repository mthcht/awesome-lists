rule Worm_Win32_Vabukey_A_2147640183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vabukey.A"
        threat_id = "2147640183"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vabukey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ViRu$ ABU_KISS" ascii //weight: 1
        $x_1_2 = {56 21 52 75 24 73 20 41 42 55 2d 4b 21 53 24 00}  //weight: 1, accuracy: High
        $x_1_3 = "ABU_ALASAD  ((\"||\"))" ascii //weight: 1
        $x_1_4 = {4e 65 57 20 56 69 43 74 49 6d 20 42 52 43 41 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 73 6e 62 6c 6f 63 6b 63 68 65 63 6b 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = "VIRUS ABU_KI$$" wide //weight: 1
        $x_1_7 = {41 00 42 00 55 00 41 00 4c 00 41 00 53 00 41 00 44 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

