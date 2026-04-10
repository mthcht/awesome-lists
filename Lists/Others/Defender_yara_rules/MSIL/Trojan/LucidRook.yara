rule Trojan_MSIL_LucidRook_DA_2147966691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LucidRook.DA!MTB"
        threat_id = "2147966691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LucidRook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 72 96 6e 4d 70 72 96 6e 4d 70 0c 1d 28 ?? ?? ?? 0a 0d 25 28 ?? ?? ?? 0a 26 08 28 ?? ?? ?? 0a 26 06 28 ?? ?? ?? 0a 13 04 72 b4 6e 4d 70 28 ?? ?? ?? 0a 11 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 05 09 72 ce 6e 4d 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

