rule Trojan_MSIL_ImpulseClipper_A_2147839033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ImpulseClipper.A!MTB"
        threat_id = "2147839033"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ImpulseClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RegSvc.Properties" ascii //weight: 2
        $x_2_2 = "RegSvc.RegSvc.resources" ascii //weight: 2
        $x_2_3 = "ImpulseClipper.Properties.Resources.resources" ascii //weight: 2
        $x_1_4 = "Clipboard" ascii //weight: 1
        $x_1_5 = "Mutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

