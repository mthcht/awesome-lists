rule Worm_MSIL_Pavnir_A_2147706973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Pavnir.A"
        threat_id = "2147706973"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pavnir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 73 00 6e 00 72 00 2e 00 74 00 78 00 74 00 ?? ?? 73 00 6e 00 72 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6c 00 69 00 73 00 74 00 70 00 68 00 72 00 61 00 73 00 65 00 2e 00 74 00 78 00 74 00 ?? ?? 5c 00 6c 00 69 00 73 00 74 00 70 00 68 00 72 00 61 00 73 00 65 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 52 00 75 00 6e 00 ?? ?? 6d 00 73 00 63 00 65 00 49 00 6e 00 74 00 65 00 72 00 ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\my mail file\\fsta.txt" wide //weight: 1
        $x_1_5 = "/filesend/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

