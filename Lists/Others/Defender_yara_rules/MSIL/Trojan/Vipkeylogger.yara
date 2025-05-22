rule Trojan_MSIL_Vipkeylogger_CE_2147941920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vipkeylogger.CE!MTB"
        threat_id = "2147941920"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vipkeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 12 02 28 ?? 00 00 0a 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 13 08 04 03 6f ?? 00 00 0a 59 13 09 11 09 19 fe 04 16 fe 01}  //weight: 4, accuracy: Low
        $x_1_2 = {1b 13 04 38 ?? 01 00 00 03 6f ?? 00 00 0a 04 fe 04 16 fe 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

