rule Trojan_MSIL_AgentSt_J_2147742407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AgentSt.J!ibt"
        threat_id = "2147742407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentSt"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 1a 28 10 00 00 0a 72 ?? 00 00 70 72 ?? 00 00 70 28 06 00 00 06 28 11 00 00 0a 13 07}  //weight: 1, accuracy: Low
        $x_1_2 = {70 28 06 00 00 06 11 07 6f 12 00 00 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {11 08 28 14 00 00 0a 26}  //weight: 1, accuracy: High
        $x_1_4 = {02 08 18 6f 16 00 00 0a 1f 10 28 17 00 00 0a 0d}  //weight: 1, accuracy: High
        $x_1_5 = {07 09 06 08 18 5b 06 6f 18 00 00 0a 5d 6f 19 00 00 0a 61 d1 8c 18 00 00 01 28 1a 00 00 0a 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

