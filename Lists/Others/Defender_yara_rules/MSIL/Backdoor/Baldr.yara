rule Backdoor_MSIL_Baldr_YA_2147734996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Baldr.YA!MTB"
        threat_id = "2147734996"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Baldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "BALDR VERSION : {" wide //weight: 6
        $x_1_2 = "Cookies Count : {" wide //weight: 1
        $x_1_3 = "Passwords Count : {" wide //weight: 1
        $x_1_4 = "Autofills Count : {" wide //weight: 1
        $x_1_5 = "Cards Count : {" wide //weight: 1
        $x_1_6 = "History Count : {" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

