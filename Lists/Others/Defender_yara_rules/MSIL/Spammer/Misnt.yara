rule Spammer_MSIL_Misnt_A_2147696645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:MSIL/Misnt.A"
        threat_id = "2147696645"
        type = "Spammer"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Misnt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 6e 6c 75 63 6b 79 49 6e 64 65 78 00 67 6f 6f 64 4d 61 69 6c}  //weight: 1, accuracy: High
        $x_1_2 = {72 65 61 64 79 54 6f 57 6f 72 6b 00 61 72 67 73 00 73 65 74 43 6f 6e 66 69 67}  //weight: 1, accuracy: High
        $x_1_3 = {6f 77 6e 44 6f 6d 61 69 6e 00 6b 65 79 00 6d 61 69 6c 65 72}  //weight: 1, accuracy: High
        $x_1_4 = {63 66 67 00 6c 67 63 00}  //weight: 1, accuracy: High
        $x_1_5 = "&gate=" wide //weight: 1
        $x_1_6 = ".ru" wide //weight: 1
        $x_5_7 = "src\\mb_bt\\" ascii //weight: 5
        $x_1_8 = "s5list_prod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

