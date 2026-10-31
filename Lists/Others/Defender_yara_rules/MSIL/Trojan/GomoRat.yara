rule Trojan_MSIL_GomoRat_AN_2147981125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GomoRat.AN!MTB"
        threat_id = "2147981125"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GomoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Global\\GomoRat_UM2" ascii //weight: 2
        $x_1_2 = "AsyncCallback" ascii //weight: 1
        $x_1_3 = "RemoteCertificateValidationCallback" ascii //weight: 1
        $x_1_4 = "set_ServerCertificateValidationCallback" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "ToBase64String" ascii //weight: 1
        $x_1_7 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_8 = "SetWindowsHookExW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_GomoRat_EN_2147981269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GomoRat.EN!MTB"
        threat_id = "2147981269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GomoRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "de344385-3a4d-45b2-a2a7-8722135f484d" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\ASIO" ascii //weight: 1
        $x_1_3 = "AUXLine21Data" ascii //weight: 1
        $x_1_4 = "MPEG1Payload" ascii //weight: 1
        $x_1_5 = "ScriptCommand" ascii //weight: 1
        $x_2_6 = {2f 00 73 00 72 00 63 00 2f 00 50 00 6c 00 75 00 67 00 69 00 6e 00 2d 00 [0-31] 2f 00 6f 00 62 00 6a 00 2f 00 [0-63] 2f 00 6e 00 65 00 74 00 34 00 37 00 32 00 2f 00 [0-31] 2e 00 70 00 64 00 62 00}  //weight: 2, accuracy: Low
        $x_2_7 = {2f 73 72 63 2f 50 6c 75 67 69 6e 2d [0-31] 2f 6f 62 6a 2f [0-63] 2f 6e 65 74 34 37 32 2f [0-31] 2e 70 64 62}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

