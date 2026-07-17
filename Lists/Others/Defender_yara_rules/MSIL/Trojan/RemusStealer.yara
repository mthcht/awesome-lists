rule Trojan_MSIL_RemusStealer_ATXB_2147973536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemusStealer.ATXB!MTB"
        threat_id = "2147973536"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemusStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 16 02 7b ?? 00 00 04 02 7b ?? 00 00 04 16 94 02 7b ?? 00 00 04 17 94 6f ?? 00 00 0a a4 ?? 00 00 01 02 7b ?? 00 00 04 02 7b ?? 00 00 04 6f ?? 00 00 0a 00 17 8c ?? 00 00 01 0a 2b 00 06 2a}  //weight: 3, accuracy: Low
        $x_2_2 = {0a 06 02 7d ?? 00 00 04 06 03 7d ?? 00 00 04 00 06 06 7b ?? 00 00 04 16 30 03 16 2b 06 06 7b ?? 00 00 04 73 ?? 00 00 0a 7d ?? 00 00 04 06 7b ?? 00 00 04 16 31 21 06 7b ?? 00 00 04 6f ?? 00 00 0a 16 31 13 06 7b ?? 00 00 04 6f ?? 00 00 0a 16 fe 02 16 fe 01 2b 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

