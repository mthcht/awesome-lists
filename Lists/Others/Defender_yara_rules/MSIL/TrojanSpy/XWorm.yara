rule TrojanSpy_MSIL_XWorm_AOX_2147946339_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/XWorm.AOX!MTB"
        threat_id = "2147946339"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 11 05 28 ?? 00 00 0a 13 06 28 ?? 00 00 0a 11 06 6f ?? 00 00 0a 13 07 06 28 ?? 00 00 0a 13 08 28 ?? 00 00 0a 11 08 6f ?? 00 00 0a 13 09 28 ?? 00 00 0a 13 0a 09 28 ?? 00 00 0a 13 0b 19 8d ?? 00 00 01 13 0d 11 0d 16 11 0a a2 11 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

