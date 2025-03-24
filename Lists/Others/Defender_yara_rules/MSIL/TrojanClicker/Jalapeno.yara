rule TrojanClicker_MSIL_Jalapeno_AJL_2147936850_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Jalapeno.AJL!MTB"
        threat_id = "2147936850"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jalapeno"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 04 17 13 06 2b 49 11 06 18 5d 2d 1d 11 04 08 72 93 00 00 70 02 11 06 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 26 2b 20 11 04 08 6f ?? 00 00 0a 72 93 00 00 70 02 11 06 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 26 11 06 17 58 13 06 11 06 06 31 b2}  //weight: 3, accuracy: Low
        $x_1_2 = {16 0a 02 7b 0b 00 00 04 0d 12 03 28 ?? 00 00 0a 0b 16 0c 2b 12 07 08 6f ?? 00 00 0a 13 04 06 11 04 58 0a 08 17 58 0c 08 07 6f ?? 00 00 0a 32 e5}  //weight: 1, accuracy: Low
        $x_2_3 = "Tempbuild\\Adizuk\\obj\\Release\\Adizuk.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

