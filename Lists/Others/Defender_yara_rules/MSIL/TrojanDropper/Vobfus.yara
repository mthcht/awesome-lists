rule TrojanDropper_MSIL_Vobfus_A_2147683878_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Vobfus.A"
        threat_id = "2147683878"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vobfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 04 02 28 24 00 00 0a 14 7e 33 00 00 0a 7e 33 00 00 0a 16 16 7e 33 00 00 0a 14 12 ?? 12 ?? 28 16 00 00 06 26}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 04 03 28 24 00 00 0a 28 27 00 00 0a 39}  //weight: 1, accuracy: High
        $x_1_3 = {6f 30 00 00 0a 28 22 00 00 0a 28 23 00 00 0a 11 ?? 6f 31 00 00 0a 6f 15 00 00 0a 28 13 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

