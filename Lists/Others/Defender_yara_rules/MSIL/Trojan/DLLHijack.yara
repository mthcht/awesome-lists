rule Trojan_MSIL_DLLHijack_BAA_2147956593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DLLHijack.BAA!MTB"
        threat_id = "2147956593"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 11 04 91 1f 41 33 5b 06 11 04 17 58 91 1f 41 33 51 06 11 04 18 58 91 1f 41 33 47 06 11 04 19 58 91 1f 41 33 3d 16 13 05 2b 11 06 11 04 11 05 58 07 11 05 91 9c 11 05 17 58 13 05 11 05 07 8e 69 2f 0a 11 04 11 05 58 06 8e 69 32 de 11 04 07 8e 69 58 06 8e 69 2f 1a 06 11 04 07 8e 69 58 16 9c 2b 0f 11 04 17 58 13 04 11 04 06 8e 69 1a 59 32 8e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

