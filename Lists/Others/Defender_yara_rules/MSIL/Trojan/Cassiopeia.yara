rule Trojan_MSIL_Cassiopeia_MBJ_2147838920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cassiopeia.MBJ!MTB"
        threat_id = "2147838920"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cassiopeia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 31 00 00 0a 0c 06 08 28 32 00 00 0a 72 ?? ?? ?? 70 6f 33 00 00 0a 6f 34 00 00 0a 6f 35 00 00 0a 06 18 6f 36 00 00 0a 06 6f 37 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7}  //weight: 5, accuracy: Low
        $x_1_2 = "AES_Decryptor" ascii //weight: 1
        $x_1_3 = "GetTheResource" ascii //weight: 1
        $x_1_4 = "Split" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cassiopeia_ACA_2147905248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cassiopeia.ACA!MTB"
        threat_id = "2147905248"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cassiopeia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 06 18 6f 37 00 00 0a 06 6f 38 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f 39 00 00 0a 0b de 11 de 0f 25 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

