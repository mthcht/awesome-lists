rule Trojan_MSIL_Pretoria_SK_2147917681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Pretoria.SK!MTB"
        threat_id = "2147917681"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pretoria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 7e 02 00 00 04 8e 69 5d 0b 02 06 02 06 91 7e 02 00 00 04 07 91 61 d2 9c 06 17 58 0a 06 02 8e 69 32 dd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

