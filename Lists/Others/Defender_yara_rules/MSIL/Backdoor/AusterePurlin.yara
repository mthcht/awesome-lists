rule Backdoor_MSIL_AusterePurlin_B_2147975418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/AusterePurlin.B!dha"
        threat_id = "2147975418"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AusterePurlin"
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

