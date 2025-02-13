rule TrojanDropper_MSIL_XWorm_OO_2147919113_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/XWorm.OO!MTB"
        threat_id = "2147919113"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 02 28 25 00 00 0a 7e 09 00 00 04 15 16 28 26 00 00 0a 16 9a 28 17 00 00 06 28 ?? ?? ?? 0a de 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

