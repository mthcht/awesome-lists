rule Trojan_MSIL_RedLinePacker_2147813639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLinePacker!MTB"
        threat_id = "2147813639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLinePacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 01 00 00 2b 0a 28 12 00 00 0a 25 6f 13 00 00 0a 0b 06 20 ?? ?? ?? ?? 28 01 00 00 06 0c 12 02 28 14 00 00 0a 74 01 00 00 1b 0d 20 ?? ?? ?? ?? 28 02 00 00 2b 09 6f 15 00 00 0a 09 16 09 8e 69 28 10 00 00 0a 12 02 28 16 00 00 0a 06 16 06 8e 69}  //weight: 1, accuracy: Low
        $x_1_2 = {28 10 00 00 0a 07 20 01 00 00 11 6f 17 00 00 0a 80 01 00 00 04 28 18 00 00 0a 14 fe 06 03 00 00 06 73 19 00 00 0a 6f 1a 00 00 0a 25 6f 1b 00 00 0a 26 7e 01 00 00 04 16 91 7e 01 00 00 04 17 91 1e 62 60 7e 01 00 00 04 18 91 1f 10 62 60}  //weight: 1, accuracy: High
        $x_1_3 = {7e 01 00 00 04 19 91 1f 18 62 60 6f 1c 00 00 0a 25 6f 1d 00 00 0a 8e 69 8d 06 00 00 01 13 04 11 04 8e 2c 05 11 04 16 02 a2 14 11 04 6f 1e 00 00 0a 13 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

