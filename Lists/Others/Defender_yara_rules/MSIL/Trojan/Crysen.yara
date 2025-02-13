rule Trojan_MSIL_Crysen_RS_2147828546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysen.RS!MTB"
        threat_id = "2147828546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DcRatByqwqdanchun" wide //weight: 1
        $x_1_2 = "Paste_bin" wide //weight: 1
        $x_1_3 = "VmlydHVhbFByb3RlY3Q=" wide //weight: 1
        $x_1_4 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Crysen_MBAS_2147839697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Crysen.MBAS!MTB"
        threat_id = "2147839697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 2b 3f 08 6f ?? 00 00 0a 2b 0c 28 ?? 00 00 0a 03 6f ?? 00 00 0a 0a 73 ?? 00 00 0a 0d 09 06 2b 10}  //weight: 1, accuracy: Low
        $x_1_2 = {fe eb e8 eb de eb db eb d5 eb eb eb f6 eb fc eb c7 eb d8 eb d6 eb ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

