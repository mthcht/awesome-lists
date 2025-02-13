rule Backdoor_MSIL_XenoRat_BSA_2147927609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XenoRat.BSA!MTB"
        threat_id = "2147927609"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "xeno rat client" ascii //weight: 10
        $x_5_2 = {1b 30 06 00 84 0b 00 00 10 00 00 11 12 00 14 7d 04 00 00 04 14 0b 72 64 05 00 70 0c 08 18 28 32 00 00 0a 28 33 00 00 0a 16 28 34 00 00 0a 26 21 00 60 40 00 00 00 00 00 e0 0d 20 b7 50 00 00 13 04 11 04 8d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_XenoRat_BSA_2147927609_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/XenoRat.BSA!MTB"
        threat_id = "2147927609"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XenoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "xeno rat client" ascii //weight: 10
        $x_10_2 = "xeno_rat_client" ascii //weight: 10
        $x_10_3 = "\\xeno-rat\\Plugins" ascii //weight: 10
        $x_6_4 = "SendAsync" ascii //weight: 6
        $x_6_5 = "IAsyncStateMachine" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_6_*))) or
            ((2 of ($x_10_*) and 1 of ($x_6_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

