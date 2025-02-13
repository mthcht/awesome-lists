rule Trojan_MSIL_Serten_A_2147743044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Serten.A!MSR"
        threat_id = "2147743044"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Serten"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 08 91 1f 70 61 0d 02 8e 69 17 d6 8d 60 00 00 01 13 04 08 13 06 16 13 07 2b 35 11 04 11 07 02 11 07 91 09 61 07 11 05 91 61 b4 9c 11 05 03 6f ?? ?? ?? 0a 17 da fe 01 13 08 11 08 2c 05 16 13 05 2b 07 00 11 05 17 d6 13 05 11 07 17 d6 13 07 11 07 11 06 31 c5 11 04 08 17 da 17 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

