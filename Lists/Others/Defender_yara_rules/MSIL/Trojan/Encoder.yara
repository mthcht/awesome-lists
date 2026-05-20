rule Trojan_MSIL_Encoder_JX_2147969726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Encoder.JX!MTB"
        threat_id = "2147969726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 30 04 00 70 28 51 00 00 0a 2d 52 28 7a 00 00 0a 19 17 73 68 00 00 0a 13 16 20 00 1c 03 00 8d 52 00 00 01 13 17 11 16 11 17 16 20 00 1c 03 00 6f 74 00 00 0a 26 72 30 04 00 70 11 17 28 a8 00 00 0a 11 16 6f 78 00 00 0a 11 16 6f 75 00 00 0a de 0c}  //weight: 2, accuracy: High
        $x_2_2 = {73 40 00 00 0a 25 72 30 04 00 70 6f 41 00 00 0a 25 17 6f 45 00 00 0a 28 47 00 00 0a 26 28 7a 00 00 0a 73 6f 00 00 0a 28 70 00 00 0a 20 00 1c 03 00 6a 31 0b 02 28 7a 00 00 0a 28 1f 00 00 06 73 40 00 00 0a 25 72 72 04 00 70 28 7a 00 00 0a 72 ba 04 00 70 28 88 00 00 0a 6f 42 00 00 0a 25 17 6f a9 00 00 0a 25 17 6f 46 00 00 0a 25 72 be 04 00 70 6f 41 00 00 0a 28 47 00 00 0a 26 28 94 00 00 0a 6f 99 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

