rule Backdoor_MSIL_SeaMonkey_B_2147967679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/SeaMonkey.B!dha"
        threat_id = "2147967679"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SeaMonkey"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yyq.erxpruPrgnqcH" ascii //weight: 1
        $x_1_2 = "frgnqcHebSxpruP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

