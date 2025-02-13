rule Trojan_MSIL_Nancat_MBFV_2147902909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nancat.MBFV!MTB"
        threat_id = "2147902909"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nancat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 02 11 06 1f 16 5d 91 13 0c}  //weight: 1, accuracy: High
        $x_1_2 = {11 0b 11 0c 61 13 0e}  //weight: 1, accuracy: High
        $x_1_3 = {11 01 11 09 11 0f 11 07 5d d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nancat_MBFV_2147902909_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nancat.MBFV!MTB"
        threat_id = "2147902909"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nancat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 00 09 4c 00 6f 00 61 00 64}  //weight: 1, accuracy: High
        $x_1_2 = "GdROWCvfPYl49jeJeH.HaCVjZ3hi7tI4uoy8N" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

