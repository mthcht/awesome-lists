rule Trojan_MSIL_ExMatter_MA_2147896637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ExMatter.MA!MTB"
        threat_id = "2147896637"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ExMatter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 fe 01 2b 01 16 0c 08 2c 05 00 17 0d de 16 00 16 0d de 11 26 00 7e ?? ?? ?? 04 28 ?? ?? ?? 0a 00 16 0d de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

