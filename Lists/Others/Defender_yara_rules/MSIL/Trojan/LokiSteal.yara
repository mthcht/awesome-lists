rule Trojan_MSIL_LokiSteal_VN_2147762156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LokiSteal.VN!MTB"
        threat_id = "2147762156"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 07 19 8d ?? ?? ?? 01 80 ?? ?? ?? 04 7e ?? ?? ?? 04 16 7e ?? ?? ?? 04 a2 7e ?? ?? ?? 04 17 7e ?? ?? ?? 04 a2 02 11 06 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 28 ?? ?? ?? 06 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

