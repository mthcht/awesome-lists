rule Trojan_MSIL_Ekidoa_A_2147712305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ekidoa.A!bit"
        threat_id = "2147712305"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ekidoa"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 65 69 6e 00 68 68 68 68 00 55 6e 5a 69 70}  //weight: 1, accuracy: High
        $x_1_2 = "daoL" wide //weight: 1
        $x_1_3 = "tniopyrtnE" wide //weight: 1
        $x_1_4 = "ekovnI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

