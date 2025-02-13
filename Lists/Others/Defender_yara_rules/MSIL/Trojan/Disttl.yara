rule Trojan_MSIL_Disttl_QX_2147794523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disttl.QX!MTB"
        threat_id = "2147794523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disttl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {15 0a 28 04 00 00 0a 02 6f 05 00 00 0a 0b 07 13 04 16 13 05 2b 40 11 04 11 05 91 0c 06 08 1f 18 62 61 0a 16 0d 2b 25 06 6a 20 00 00 00 80 6e 5f 20 00 00 00 80 6e 33 0c 06 17 62 20 b7 1d c1 04 61 0a 2b 04 06 17 62 0a 09 17 58 0d 09 1e 32 d7 11 05 17 58 13 05 11 05 11 04 8e 69 32 b8 06 2a}  //weight: 1, accuracy: High
        $x_1_2 = {0b 02 03 61 0c 08 1f 11 5a 1f 1b 5b 0c 07 1d 08 58 6a 16 6f 08 00 00 0a 26 1e 8d 07 00 00 01 0d 07 09 16 1a 6f 09 00 00 0a 26 09 16 28 0a 00 00 0a 20 68 dc 2d 7d 61 1f 64 59 13 04 07 09 16 1a 6f 09 00 00 0a 26 09 16 28 0a 00 00 0a 1b 59 20 2f 6a f2 1c 61 13 05 07 11 04 6a 16 6f 08 00 00 0a 26 11 05 8d 07 00 00 01 0d 07 09 16 11 05 6f 09 00 00 0a}  //weight: 1, accuracy: High
        $x_1_3 = "Discord" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

