rule Trojan_MSIL_GrowtopiaKeylogger_A_2147836643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GrowtopiaKeylogger.A!MTB"
        threat_id = "2147836643"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GrowtopiaKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 02 26 16 7e 05 00 00 04 73 09 00 00 0a 0a 06 20 ?? ?? 00 00 28 3d 00 00 06 02 6a 20 ?? ?? 00 00 28 3e 00 00 06 06 20 ?? ?? 00 00 28 3f 00 00 06 28 0c 00 00 06 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {2b 02 26 16 02 20 ?? ?? 00 00 28 40 00 00 06 0a 20 ?? ?? 00 00 28 36 00 00 06 06 20 ?? ?? 00 00 28 41 00 00 06 0b 07 2a}  //weight: 2, accuracy: Low
        $x_2_3 = {09 11 04 11 05 11 06 73 ?? 00 00 0a 13 0a 20 ?? ?? 00 00 17 58 28 0d 00 00 06 20 ?? ?? 00 00 73 ?? 00 00 0a 13 0b 11 0b 17 20 ?? ?? 00 00 28 2b 00 00 06 11 0b 11 07 11 08 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

