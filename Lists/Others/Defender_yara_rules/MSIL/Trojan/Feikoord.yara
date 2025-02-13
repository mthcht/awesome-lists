rule Trojan_MSIL_Feikoord_A_2147711327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Feikoord.A!bit"
        threat_id = "2147711327"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Feikoord"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 02 00 00 04 06 7e 02 00 00 04 06 91 7e 01 00 00 04 06 7e 01 00 00 04 28 04 00 00 06 5d 91 61 28 16 00 00 0a 9c 06 17 58 0a 06 7e 02 00 00 04 28 04 00 00 06 32 c9}  //weight: 1, accuracy: High
        $x_1_2 = {0a 16 0b 2b 25 06 28 17 00 00 06 72 ?? ?? ?? ?? 07 8c 39 00 00 01 28 52 00 00 0a 6f 53 00 00 0a 28 54 00 00 0a 0a 07 17 58 0b 07 28 1b 00 00 06 32 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

