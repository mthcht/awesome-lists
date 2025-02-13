rule Worm_MSIL_Mieka_A_2147688806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Mieka.A"
        threat_id = "2147688806"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mieka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 69 6d 65 72 5f 6b 69 65 6d 74 72 61 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\Systems_Search.exe" wide //weight: 1
        $x_1_3 = "System_explorer.exe" wide //weight: 1
        $x_1_4 = {41 00 70 00 70 00 43 00 61 00 63 00 68 00 65 00 ?? ?? 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 41 00 70 00 70 00 43 00 61 00 63 00 68 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {43 00 3a 00 5c 00 ?? ?? 44 00 3a 00 5c 00 ?? ?? 45 00 3a 00 5c 00 ?? ?? 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 ?? ?? 78 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

