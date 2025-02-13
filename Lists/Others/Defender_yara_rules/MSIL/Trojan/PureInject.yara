rule Trojan_MSIL_PureInject_MBAK_2147840357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureInject.MBAK!MTB"
        threat_id = "2147840357"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Qpbjyrrpsxznsfiv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

