rule TrojanDropper_MSIL_AsyncRat_NITA_2147943277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/AsyncRat.NITA!MTB"
        threat_id = "2147943277"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 8e 69 8d 10 00 00 01 0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 06 2a}  //weight: 2, accuracy: High
        $x_1_2 = {7e 01 00 00 04 28 ?? 00 00 06 13 0d 28 ?? 00 00 0a 13 0e 11 0e 72 87 00 00 70 28 ?? 00 00 0a 13 15 12 15 fe 16 16 00 00 01 6f 19 00 00 0a 11 0b 16 6f 1a 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0f 11 0f 11 0d 28 ?? 00 00 0a 11 0f 28 ?? 00 00 0a 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

