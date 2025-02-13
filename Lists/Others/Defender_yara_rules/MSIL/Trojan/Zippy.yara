rule Trojan_MSIL_Zippy_NEAA_2147836650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zippy.NEAA!MTB"
        threat_id = "2147836650"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zippy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a de 0a 07 2c 06 07 6f 05 00 00 0a dc 28 06 00 00 0a 72 ?? 00 00 70 28 07 00 00 0a 06 28 08 00 00 0a 20 e8 03 00 00 28 09 00 00 0a 28 06 00 00 0a 72 ?? 00 00 70 28 07 00 00 0a 28 0a 00 00 0a 26 de 03}  //weight: 10, accuracy: Low
        $x_5_2 = "itself.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

