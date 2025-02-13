rule Trojan_MSIL_Faikdal_A_2147712382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Faikdal.A"
        threat_id = "2147712382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Faikdal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 00 63 00 6f 00 6d 00 [0-32] 68 00 [0-24] 74 00 [0-24] 74 00 [0-24] 70 00 [0-24] 3a 00 [0-24] 2f 00 [0-24] 2f 00}  //weight: 10, accuracy: Low
        $x_1_2 = "downloadcfile" ascii //weight: 1
        $x_1_3 = "killother" ascii //weight: 1
        $x_1_4 = "savetolog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Faikdal_A_2147712382_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Faikdal.A"
        threat_id = "2147712382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Faikdal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 74 00 6d 00 6c 00 [0-32] 68 00 [0-24] 74 00 [0-24] 74 00 [0-24] 70 00 [0-24] 3a 00 [0-24] 2f 00 [0-24] 2f 00}  //weight: 10, accuracy: Low
        $x_1_2 = "downloadcfile" ascii //weight: 1
        $x_1_3 = "killother" ascii //weight: 1
        $x_1_4 = "savetolog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Faikdal_B_2147716105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Faikdal.B"
        threat_id = "2147716105"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Faikdal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "downloadcfile" ascii //weight: 1
        $x_1_2 = "killother" ascii //weight: 1
        $x_1_3 = "savetolog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

