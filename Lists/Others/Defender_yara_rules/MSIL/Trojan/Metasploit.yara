rule Trojan_MSIL_Metasploit_AMBF_2147901828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Metasploit.AMBF!MTB"
        threat_id = "2147901828"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Metasploit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 49 06 07 06 8e 69 5d 93 61 d1 53 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d dd}  //weight: 1, accuracy: High
        $x_1_2 = {0a 00 0b 07 6f ?? 00 00 0a 0c 08 06 16 06 8e 69 6f ?? 00 00 0a 0d 28 ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 2b 00 11 05 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

