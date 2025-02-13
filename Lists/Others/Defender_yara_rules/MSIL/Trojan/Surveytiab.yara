rule Trojan_MSIL_Surveytiab_A_2147711303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Surveytiab.A"
        threat_id = "2147711303"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Surveytiab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "://goo.gl/sjMn9B" wide //weight: 4
        $x_4_2 = "://goo.gl/EINfQn" wide //weight: 4
        $x_1_3 = "gamesofpc.com/how-to-download-individual-key/" wide //weight: 1
        $x_1_4 = "Download free license key of the product" wide //weight: 1
        $x_1_5 = "0CIU-SWG63-ACMJ7-FFF35-SLK8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

