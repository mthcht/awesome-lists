rule PWS_MSIL_Echelon_GG_2147762587_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Echelon.GG!MTB"
        threat_id = "2147762587"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Echelon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "credit_card" ascii //weight: 1
        $x_1_2 = "echelon.txt" ascii //weight: 1
        $x_1_3 = "post" ascii //weight: 1
        $x_1_4 = "Echelon_Dir" ascii //weight: 1
        $x_1_5 = "Password" ascii //weight: 1
        $x_1_6 = "cookies" ascii //weight: 1
        $x_1_7 = "Grabber" ascii //weight: 1
        $x_1_8 = "Monero" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule PWS_MSIL_Echelon_GG_2147762587_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Echelon.GG!MTB"
        threat_id = "2147762587"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Echelon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 fe 01 0c 78 00 14 fe [0-6] 73 [0-6] 6f [0-6] 00 00 7e [0-6] 72 [0-6] 7e [0-6] 28 [0-6] 28 [0-6] 0b 07 2c [0-2] 00 7e [0-6] 72 [0-6] 7e [0-6] 28 [0-6] 28 [0-6] 7e [0-6] 6f}  //weight: 10, accuracy: Low
        $x_1_2 = "GetStealer" ascii //weight: 1
        $x_1_3 = "Echelon_Dir" ascii //weight: 1
        $x_1_4 = "Grabber" ascii //weight: 1
        $x_1_5 = "passwordzip" ascii //weight: 1
        $x_1_6 = "Monero" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

