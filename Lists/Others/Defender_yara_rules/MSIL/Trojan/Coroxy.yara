rule Trojan_MSIL_Coroxy_SPDL_2147917893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coroxy.SPDL!MTB"
        threat_id = "2147917893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d1 13 14 11 1d 11 09 91 13 22 11 1d 11 09 11 21 11 22 61 19 11 1f 58 61 11 34 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

