rule Backdoor_MSIL_Draliz_A_2147692465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Draliz.A"
        threat_id = "2147692465"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Draliz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lizard Rat" wide //weight: 1
        $x_1_2 = "StartUDP" ascii //weight: 1
        $x_1_3 = "StopUDP" ascii //weight: 1
        $x_1_4 = "StartHTTP" ascii //weight: 1
        $x_1_5 = "StopHTTP" ascii //weight: 1
        $x_1_6 = "httprun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

