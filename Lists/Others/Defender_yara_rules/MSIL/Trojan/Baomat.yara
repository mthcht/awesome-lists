rule Trojan_MSIL_Baomat_A_2147836284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Baomat.A!MTB"
        threat_id = "2147836284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Baomat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 0b 03 73 ?? ?? 00 06 20 80 00 00 00 04 14 73 ?? ?? 00 06 0c 07 16 08 6f ?? ?? 00 06 00 07 02 8e 69 6f ?? ?? 00 06 8d ?? 00 00 01 0d 07 02 16 02 8e 69 09 16 6f ?? ?? 00 06 13 04 07 09 11 04 6f ?? ?? 00 06 26 7e f2 40 00 04 28 07 87 00 06 09 7e 89 41 00 04 28 97 87 00 06 20 12 10 00 00 28 75 86 00 06 7e a5 41 00 04 28 a3 87 00 06 7e a8 41 00 04 28 a7 87 00 06 13 05 dd 0e 00 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

