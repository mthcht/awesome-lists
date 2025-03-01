rule Trojan_MSIL_AZORult_NYA_2147826548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AZORult.NYA!MTB"
        threat_id = "2147826548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AZORult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 06 16 73 ?? ?? ?? 0a 73 ?? ?? ?? 0a 0c 08 07 6f ?? ?? ?? 0a de 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {95 a2 29 09 0b 00 00 00 ?? ?? ?? 00 16 00 00 01 00 00 00 3a 00 00 00 09 00 00 00 06 00 00 00 18 00 00 00 07 00 00 00 37 00 00 00 18 00 00 00 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

