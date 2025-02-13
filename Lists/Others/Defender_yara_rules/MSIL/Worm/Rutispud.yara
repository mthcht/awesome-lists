rule Worm_MSIL_Rutispud_A_2147637951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Rutispud.A"
        threat_id = "2147637951"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rutispud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 53 00 59 00 4e 00 00 07 55 00 44 00 50 00 00 09 53 00 54 00 4f 00 50 00 00 07 44 00 57 00 4e 00 00 07 52 00 45 00 4d 00 00 09 51 00 55 00 49 00 54 00 00 0b 47 00 45 00 54 00 46 00 46}  //weight: 1, accuracy: High
        $x_1_2 = {0f 53 00 54 00 55 00 7e 00 30 00 30 00 31 00 00 0f 53 00 54 00 55 00 7e 00 30 00 30 00 32 00 00 0f 53 00 54 00 55 00 7e 00 30 00 30 00 33 00 00 0f 53 00 54 00 55 00 7e 00 30 00 30 00 34}  //weight: 1, accuracy: High
        $x_1_3 = {2f 00 63 00 20 00 65 00 63 00 68 00 6f 00 20 00 3b 00 00 09 20 00 3e 00 3e 00 20 00 00 17 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66}  //weight: 1, accuracy: High
        $x_1_4 = {1b 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 53 00 65 00 76 00 65 00 6e}  //weight: 1, accuracy: High
        $x_1_5 = {1d 73 00 69 00 67 00 6e 00 6f 00 6e 00 73 00 2e 00 73 00 71 00 6c 00 69 00 74 00 65 00 00 33 53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 6d 00 6f 00 7a 00 5f 00 6c 00 6f 00 67 00 69 00 6e 00 73}  //weight: 1, accuracy: High
        $x_1_6 = {1f 41 00 72 00 65 00 20 00 79 00 6f 00 75 00 20 00 73 00 74 00 75 00 70 00 69 00 64 00 3f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_MSIL_Rutispud_B_2147638326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Rutispud.B"
        threat_id = "2147638326"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rutispud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "The victim has used the clipboard" wide //weight: 3
        $x_3_2 = "=FileZilla Steal=" wide //weight: 3
        $x_1_3 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\LimeWire\\" wide //weight: 1
        $x_2_4 = "127.0.0.1 www.virustotal.com" wide //weight: 2
        $x_2_5 = "windows_7full.scr" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

