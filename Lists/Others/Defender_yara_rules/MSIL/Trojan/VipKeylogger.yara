rule Trojan_MSIL_VipKeylogger_AVI_2147974587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VipKeylogger.AVI!MTB"
        threat_id = "2147974587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VipKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 16 0c 2b 29 00 07 08 61 1f 1f 5a 0b 06 07 58 1f 0d 61 0a 02 08 02 08 91 06 d2 61 07 d2 59 1d 61 d2 9c 07 02 08 91 58 0b 08 17 58 0c 00 08 02 8e 69 fe 04 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

