rule Worm_MSIL_Ainslot_A_2147683897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Ainslot.A"
        threat_id = "2147683897"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ainslot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Blackshades NET" wide //weight: 1
        $x_1_2 = "/C ping 1.1.1.1 -n 1 -w 1000 > Nul & Del" wide //weight: 1
        $x_1_3 = "Imminent" wide //weight: 1
        $x_1_4 = "Attemping to connect to: {0}:{1}" wide //weight: 1
        $x_1_5 = {53 74 61 72 74 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {5f 66 6c 6f 6f 64 69 6e 67 54 68 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_2_7 = {20 80 02 00 00 20 e0 01 00 00 28 ?? ?? ?? ?? 74 ?? ?? ?? ?? 0d 12 03 1f 50}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

