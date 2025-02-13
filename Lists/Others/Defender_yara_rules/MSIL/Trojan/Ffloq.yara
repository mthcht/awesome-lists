rule Trojan_MSIL_Ffloq_A_2147706176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ffloq.A"
        threat_id = "2147706176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ffloq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set_Expect100Continue" ascii //weight: 1
        $x_1_2 = "Firefox.Resources.resources" ascii //weight: 1
        $x_1_3 = "ConfuserEx v0." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

