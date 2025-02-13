rule Trojan_MSIL_Citadel_MBJL_2147892208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Citadel.MBJL!MTB"
        threat_id = "2147892208"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Citadel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 11 05 91 0b 02 11 05 17 d6 91 0d 18 09 d8 03 da 07 da 13 04 03 07 da 09 d6 0c 2b 08 08 20 00 01 00 00 d6 0c 08 16 32 f4}  //weight: 1, accuracy: High
        $x_1_2 = "9-5feaf84bf17b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

