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

