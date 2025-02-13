rule Worm_MSIL_Shaskooth_A_2147643302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Shaskooth.A"
        threat_id = "2147643302"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shaskooth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "taskhosth.exe" wide //weight: 2
        $x_1_2 = {74 61 73 6b 68 6f 73 74 5f 73 79 73 74 65 6d 5f 33 32 2e 50 72 6f 70 65 72 74 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {42 75 62 6c 69 73 68 65 72 5f 4c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {54 69 6d 65 72 42 75 73 71 5f 54 69 63 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {45 73 74 61 41 63 74 69 76 6f 45 6c 76 69 72 75 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

