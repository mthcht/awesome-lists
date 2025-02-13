rule Trojan_MSIL_DnInject_A_2147767355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DnInject.A!MTB"
        threat_id = "2147767355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DnInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 6d 00 61 00 7a 00 65 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = "This+program+cannot+be+run+in+DOS+mode" ascii //weight: 1
        $x_1_3 = "get_iii" ascii //weight: 1
        $x_1_4 = "B u t a" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_DnInject_B_2147767454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DnInject.B!MTB"
        threat_id = "2147767454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DnInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 28 09 00 00 06 28 18 00 00 06 0a 06 28 0d 00 00 06 2a}  //weight: 1, accuracy: High
        $x_1_2 = {00 79 65 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 6c 6f 61 64 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

