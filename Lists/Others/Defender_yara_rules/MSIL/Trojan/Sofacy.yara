rule Trojan_MSIL_Sofacy_S_2147730884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sofacy.S!MTB"
        threat_id = "2147730884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sofacy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start_Tick" ascii //weight: 1
        $x_1_2 = "screen_Tick" ascii //weight: 1
        $x_1_3 = "subject_Tick" ascii //weight: 1
        $x_1_4 = "Domain:  {0}" wide //weight: 1
        $x_1_5 = "Working: {0}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

