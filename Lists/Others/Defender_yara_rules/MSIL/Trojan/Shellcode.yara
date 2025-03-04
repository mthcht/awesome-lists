rule Trojan_MSIL_Shellcode_SK_2147909721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shellcode.SK!MTB"
        threat_id = "2147909721"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shellcode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 06 07 06 07 91 20 a0 06 00 00 59 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 13 0a 11 0a 2d e1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

