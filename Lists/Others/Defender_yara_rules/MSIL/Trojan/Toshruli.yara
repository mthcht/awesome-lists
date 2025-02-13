rule Trojan_MSIL_Toshruli_A_2147638291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Toshruli.A"
        threat_id = "2147638291"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Toshruli"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "fake3.Properties.Resources" ascii //weight: 1
        $x_1_2 = {20 b8 0b 00 00 28 ?? 00 00 0a 11 04 2d a1 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? 00 00 0a 13 06 11 06 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {38 0e 00 00 00 11 0e 6f ?? 00 00 0a 26 11 0f 17 58 13 0f 11 0f 20 18 04 00 00 32 e9 11 0e 20 ?? ?? ?? ?? 28 ?? 00 00 06 6f ?? 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

