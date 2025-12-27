rule Trojan_MSIL_ResInject_MCF_2147946229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ResInject.MCF!MTB"
        threat_id = "2147946229"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ResInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 00 38 00 31 00 6e 00 4d 00 77 00 66 00 44 00 71 00 00 15 50 00 47 00 35 00 51 00 58 00 73 00 32 00 73 00 42 00 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

