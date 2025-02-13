rule Ransom_MSIL_Chimera_AR_2147893305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Chimera.AR!MTB"
        threat_id = "2147893305"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chimera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 02 07 91 03 07 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 eb}  //weight: 1, accuracy: High
        $x_1_2 = {02 17 9a 11 05 91 28 0f 00 00 06 61 09 02 18 9a 11 05 91 28 0f 00 00 06 61 11 04 02 19 9a 11 05 91 28 0f 00 00 06 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

