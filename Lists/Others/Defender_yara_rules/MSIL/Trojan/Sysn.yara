rule Trojan_MSIL_Sysn_NS_2147896737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sysn.NS!MTB"
        threat_id = "2147896737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sysn"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8e 69 17 63 8f ?? 00 00 01 25 47 06 1a 58 4a d2 61 d2 52 28 ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "Authennticate @2023" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

