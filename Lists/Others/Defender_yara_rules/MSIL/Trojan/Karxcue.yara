rule Trojan_MSIL_Karxcue_A_2147640844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Karxcue.A"
        threat_id = "2147640844"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Karxcue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2e 00 66 00 61 00 73 00 [0-8] 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 41 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 [0-8] 48 00 69 00 64 00 64 00 65 00 6e 00}  //weight: 3, accuracy: Low
        $x_2_2 = "arxFucker.Resources" wide //weight: 2
        $x_1_3 = "Fuck You!" wide //weight: 1
        $x_1_4 = "Software\\Autodesk\\AutoCAD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

