rule TrojanDropper_MSIL_Zusy_NITF_2147946884_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Zusy.NITF!MTB"
        threat_id = "2147946884"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {22 00 00 0a 6f ?? 00 00 0a 0a 1d 28 ?? 00 00 0a 06 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 07 28 ?? 00 00 0a 2d 10 06 07 17 28 ?? 00 00 0a 07 18 28 ?? 00 00 06 26 7e 28 00 00 0a 72 2b 02 00 70 17 6f ?? 00 00 0a 0c}  //weight: 2, accuracy: Low
        $x_1_2 = {14 13 10 73 16 00 00 06 13 11 28 16 00 00 0a 0a 28 2e 00 00 0a 72 09 03 00 70 28 13 00 00 0a 0b 11 11 06 07 28 17 00 00 0a 7d 07 00 00 04 7e 05 00 00 04 2c 16 72 13 03 00 70 11 11 7b 07 00 00 04 28 13 00 00 0a 28 09 00 00 06}  //weight: 1, accuracy: High
        $x_2_3 = {2c 0a 72 c5 03 00 70 28 09 00 00 06 08 02 6f 32 00 00 0a 0d 7e 05 00 00 04 2c 1c 72 ef 03 00 70 09 8e 69 8c 20 00 00 01 72 07 04 00 70 28 33 00 00 0a 28 09 00 00 06 11 11 7b 07 00 00 04 09 28 34 00 00 0a 7e 05 00 00 04 2c 0e 11 11 7b 07 00 00 04 16 28 06 00 00 06 26}  //weight: 2, accuracy: High
        $x_2_4 = {11 11 7b 07 00 00 04 28 35 00 00 0a 13 04 72 15 04 00 70 28 09 00 00 06 16 13 05 2b 69 1a 8d 01 00 00 01 13 12 11 12 16 72 59 04 00 70 a2 11 12 17 11 05 17 58 8c 20 00 00 01 a2 11 12 18 72 69 04 00 70 a2 11 12 19 11 04 11 05 9a 6f 36 00 00 0a 1f 64 30 07 11 04 11 05 9a 2b 17 11 04 11 05 9a 16 1f 64 6f 37 00 00 0a 72 6f 04 00 70 28 13 00 00 0a a2 11 12 28 38 00 00 0a 28 09 00 00 06 11 05 17 58 13 05 11 05 19 11 04 8e 69 28 39 00 00 0a 32 89}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

