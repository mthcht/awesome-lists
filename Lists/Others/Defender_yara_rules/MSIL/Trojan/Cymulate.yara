rule Trojan_MSIL_Cymulate_MBCI_2147849167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cymulate.MBCI!MTB"
        threat_id = "2147849167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cymulate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {20 c8 00 00 00 28 ?? 00 00 0a 72 c4 57 00 70 28 ?? 00 00 0a 8e 2d e9 2b 0a 20 c8 00 00 00 28 ?? 00 00 0a 72 fe 57 00 70 28 ?? 00 00 0a 8e 2d e9}  //weight: 10, accuracy: Low
        $x_1_2 = "CymulateDCOMInterfacesWorm" ascii //weight: 1
        $x_1_3 = "CymulateEDRRansom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Cymulate_ACY_2147895793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cymulate.ACY!MTB"
        threat_id = "2147895793"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cymulate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 16 0b 02 28 6d 00 00 0a 16 fe 01 0c 08 2c 61 00 02 28 5a 00 00 0a 0d 09 2c 51 00 00 02 73 6e 00 00 0a 03 04 05 28 6f 00 00 0a 25 0a 13 04 00 06 16 6a 16 6a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

