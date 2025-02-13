rule Trojan_MSIL_RedLineStealz_A_2147924577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealz.A!MTB"
        threat_id = "2147924577"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "38F431A549411AEB32810068A4C83250B2D31E15" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

