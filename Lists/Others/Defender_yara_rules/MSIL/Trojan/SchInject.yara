rule Trojan_MSIL_SchInject_VN_2147758429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SchInject.VN!MTB"
        threat_id = "2147758429"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SchInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 09 72 ?? ?? ?? 70 18 18 8d ?? ?? ?? 01 25 17 18 8d ?? ?? ?? 01 25 16 7e ?? ?? ?? 04 a2 25 17 72 ?? ?? ?? 70 a2 a2 28 ?? ?? ?? 0a 26 72 ?? ?? ?? 70 13 ?? 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

