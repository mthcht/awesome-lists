rule Trojan_MSIL_DeepSea_MCF_2147946376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DeepSea.MCF!MTB"
        threat_id = "2147946376"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DeepSea"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4d05-a254-420565b05f21" ascii //weight: 1
        $x_1_2 = {54 00 65 00 74 00 72 00 69 00 73 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65}  //weight: 1, accuracy: High
        $x_1_3 = {57 bf b6 29 09 1e 00 00 00 fa 01 33 00 16 00 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

