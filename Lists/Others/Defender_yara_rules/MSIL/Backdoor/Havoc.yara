rule Backdoor_MSIL_Havoc_KA_2147892128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Havoc.KA!MTB"
        threat_id = "2147892128"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Havoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 09 6f 03 00 00 0a 0b 06 1b 62 06 58 07 d2 6e 58 0a 09 17 58 0d 09 08}  //weight: 5, accuracy: High
        $x_5_2 = {03 50 08 06 07 d3 58 47 9c 07 17 58 0b 08 17 58 0c 08 04 05 58}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Havoc_KAB_2147924320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Havoc.KAB!MTB"
        threat_id = "2147924320"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Havoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 04 00 00 0a 7e 01 00 00 04 8e 69 28 05 00 00 0a 20 00 10 00 00 1f 40 28 01 00 00 06 0a 7e 01 00 00 04 16 06 7e 01 00 00 04 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

