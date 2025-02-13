rule Trojan_MSIL_Vasinsitiva_A_2147720092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vasinsitiva.A!bit"
        threat_id = "2147720092"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vasinsitiva"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AntiUAC" ascii //weight: 1
        $x_1_2 = "hacking_live_botnet_lets_go" wide //weight: 1
        $x_1_3 = {5f 00 2e 00 65 00 78 00 65 00 [0-16] 72 00 75 00 6e 00 61 00 73 00 41 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_2_4 = {07 09 11 05 b7 19 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? b9 08 11 05 6c 23 ?? ?? ?? ?? ?? ?? ?? ?? 5b 28 ?? ?? ?? ?? 11 04 6c 5d 23 ?? ?? ?? ?? ?? ?? ?? ?? 58 28 ?? ?? ?? ?? b7 17 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6a 61 b7 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0b 11 05 19 6a d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

