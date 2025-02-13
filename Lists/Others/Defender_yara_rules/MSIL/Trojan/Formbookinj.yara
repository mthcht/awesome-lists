rule Trojan_MSIL_Formbookinj_GL_2147778575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Formbookinj.GL!MTB"
        threat_id = "2147778575"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Formbookinj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 02 02 8e 69 17 59 91 1f 70 61 0b 02 8e 69 17 58 8d ?? ?? ?? ?? 0c 16 0d 16 13 04 2b 30 00 08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f ?? ?? ?? ?? 17 59 fe 01 13 05 11 05 2c 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

