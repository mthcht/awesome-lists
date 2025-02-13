rule Trojan_MSIL_Sdum_RZAA_2147916432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sdum.RZAA!MTB"
        threat_id = "2147916432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sdum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 02 06 91 66 d2 9c 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 20 ?? 00 00 00 59 d2 81 ?? 00 00 01 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 58 d2 81 ?? 00 00 01 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d b9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

