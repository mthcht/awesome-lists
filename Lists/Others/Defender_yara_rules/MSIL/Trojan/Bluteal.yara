rule Trojan_MSIL_Bluteal_B_2147754729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bluteal.B!MTB"
        threat_id = "2147754729"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bluteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 6b 00 00 06 00 28 6b 00 00 06 00 28 6b 00 00 06 00 28 6b 00 00 06 00 28 6b 00 00 06 00 28 6b 00 00 06 00 28 6b 00 00 06 00 28 6b 00 00 06 00 28 6b 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {13 05 11 05 2d d5 07 73 ?? ?? ?? ?? 0d 00 72 d8 02 00 70 13 06 1e 8d 45 00 00 01 13 07 73 ?? ?? ?? ?? 13 08 16 13 0c 2b 21 00 11 07 11 0c 11 06 08 11 06 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

