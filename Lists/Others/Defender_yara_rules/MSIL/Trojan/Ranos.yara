rule Trojan_MSIL_Ranos_A_2147685692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ranos.A"
        threat_id = "2147685692"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ranos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ServStart" ascii //weight: 1
        $x_1_2 = {68 65 78 32 42 79 74 00}  //weight: 1, accuracy: High
        $x_1_3 = "Now Executing Custom Application..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ranos_OJC_2147823556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ranos.OJC!MTB"
        threat_id = "2147823556"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ranos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 05 b7 08 11 05 18 6a d8 b7 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 05 17 6a d6 13 05 11 05 11 06 31 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

