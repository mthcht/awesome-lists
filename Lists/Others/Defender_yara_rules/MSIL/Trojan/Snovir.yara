rule Trojan_MSIL_Snovir_F_2147828908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snovir.F!MTB"
        threat_id = "2147828908"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snovir"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 91 06 61 00 23 ?? ?? ?? ?? ?? ?? ?? ?? 23 ?? ?? ?? ?? ?? ?? ?? ?? 28 ?? ?? ?? ?? 58 28 ?? ?? ?? ?? 61 d2 9c 06 17 58 0a 06 7e 03 00 00 04 8e 69 fe 04 3a bd ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

