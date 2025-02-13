rule Trojan_MSIL_Lokild_J_2147743691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lokild.J!ibt"
        threat_id = "2147743691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lokild"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "=.exe" ascii //weight: 1
        $x_1_2 = {25 47 03 06 28 ?? 00 00 06 [0-48] 61 d2 52 ?? 0c 2b 35 00 02 06 8f ?? 00 00 01}  //weight: 1, accuracy: Low
        $x_1_3 = {01 11 05 11 0a ?? ?? 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b ?? ?? 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f ?? 00 00 0a 26}  //weight: 1, accuracy: Low
        $x_1_4 = {06 02 03 28 ?? 00 00 06 02 5f 61 d2 2a 15 00 03 28}  //weight: 1, accuracy: Low
        $x_1_5 = {7e 02 00 00 04 02 7e 02 00 00 04 8e 69 5d 91 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

