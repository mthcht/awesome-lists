rule Backdoor_MSIL_Revetrat_A_2147725591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Revetrat.A!bit"
        threat_id = "2147725591"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Revetrat"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "R3Vlc3Q=" wide //weight: 1
        $x_1_2 = "*-]NK[-*" wide //weight: 1
        $x_1_3 = {41 74 6f 6d 69 63 00 4e 75 63 6c 65 61 72 5f 45 78 70 6c 6f 73 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_4 = {53 70 72 65 61 64 00 49 4e 46 41 4c 4c 00 4d 56 44}  //weight: 1, accuracy: High
        $x_1_5 = "RV_MUTEX" wide //weight: 1
        $x_1_6 = {2f 00 74 00 61 00 72 00 67 00 65 00 74 00 3a 00 77 00 69 00 6e 00 65 00 78 00 65 00 [0-4] 2f 00 77 00 69 00 6e 00 33 00 32 00 69 00 63 00 6f 00 6e 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_7 = "HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR\\0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

