rule Trojan_MSIL_BHO_B_2147650561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BHO.B"
        threat_id = "2147650561"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BHO"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {38 02 00 00 00 26 16 00 7e ?? 00 00 0a 7e ?? 00 00 04 17 6f ?? 00 00 0a 0a 06 14 fe 01 16}  //weight: 2, accuracy: Low
        $x_1_2 = "BHOKEYNAME" ascii //weight: 1
        $x_1_3 = "RegisterBHO" ascii //weight: 1
        $x_1_4 = "Rama Krishna" ascii //weight: 1
        $x_1_5 = "Automatically adds a random signatures" wide //weight: 1
        $x_1_6 = "AutoSig.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

