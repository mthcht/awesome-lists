rule Trojan_MSIL_DarkGate_ALZ_2147933801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkGate.ALZ!MTB"
        threat_id = "2147933801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 07 72 00 01 00 70 28 10 00 00 0a 0d 1d 8d 16 00 00 01 25 ?? 72 0c 01 00 70 a2 25 17 06 a2 25 18 72 b5 01 00 70 a2 25 19 08 a2 25 1a 72 ef 01 00 70 a2 25 1b 09 a2 25 1c 72 31 02 00 70 a2 28 11 00 00 0a 13 04 73 12 00 00 0a 25 72 ce 06 00 70 6f 13 00 00 0a 00 25 72 e4 06 00 70 11 04 72 38 07 00 70 28 14 00 00 0a 6f 15 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 ?? 6f 17 00 00 0a 00 25 17 6f 18 00 00 0a 00 25 17 6f 19 00 00 0a 00 13 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

