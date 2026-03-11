rule Trojan_MSIL_Nitol_VD_2147964540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nitol.VD!MTB"
        threat_id = "2147964540"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nitol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {73 04 00 00 0a 0a 06 72 01 00 00 70 6f 05 00 00 0a 06 28 06 00 00 0a 72 09 00 00 70}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

