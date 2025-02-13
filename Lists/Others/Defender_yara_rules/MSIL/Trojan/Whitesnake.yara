rule Trojan_MSIL_Whitesnake_AMBE_2147903246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Whitesnake.AMBE!MTB"
        threat_id = "2147903246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Whitesnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c 03 00 fe 0c 06 00 fe 09 00 00 fe 0c 06 00 6f ?? 00 00 0a fe 0c 02 00 fe 0c 06 00 fe 0c 02 00 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d1 9d fe 0c 06 00 20 01 00 00 00 58 fe 0e 06 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

