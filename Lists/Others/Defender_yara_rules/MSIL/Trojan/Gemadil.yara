rule Trojan_MSIL_Gemadil_A_2147719431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gemadil.A!bit"
        threat_id = "2147719431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gemadil"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Options.CheckVM" wide //weight: 1
        $x_1_2 = "Options.CheckSandbox" wide //weight: 1
        $x_1_3 = "Options.UACBypass" wide //weight: 1
        $x_1_4 = "/c copy \"{0}\" \"{1}\"" wide //weight: 1
        $x_1_5 = "/c start \"\" \"{0}\"" wide //weight: 1
        $x_2_6 = {61 00 76 00 70 00 75 00 69 00 00 00 00 00 61 00 76 00 61 00 73 00 74 00 75 00 69 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

