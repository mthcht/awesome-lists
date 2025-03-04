rule Trojan_MSIL_bladabindi_RPX_2147846536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/bladabindi.RPX!MTB"
        threat_id = "2147846536"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 5f 91 fe 09 02 00 60 61 d1 9d fe 0c 00 00 ?? ?? ?? ?? ?? 20 02 00 00 00 63 66 20 01 00 00 00 63 66 65 20 04 00 00 00 62 ?? ?? ?? ?? ?? 58 66 ?? ?? ?? ?? ?? 59 59 25 fe 0e 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

