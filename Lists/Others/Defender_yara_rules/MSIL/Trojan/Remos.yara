rule Trojan_MSIL_Remos_AMBA_2147900548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Remos.AMBA!MTB"
        threat_id = "2147900548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 11 06 1f 16 5d 91 13 0c 07 11 0a 91 11 07 58 13 0d 11 0b 11 0c 61 13 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

