rule Trojan_MSIL_Troob_CCAI_2147889436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Troob.CCAI!MTB"
        threat_id = "2147889436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Troob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 8f 28 00 00 01 25 71 ?? ?? ?? ?? 03 d2 61 d2 81 ?? ?? ?? ?? 00 06 17 58 0a 06 02 8e 69 fe 04 0c 08 2d da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

