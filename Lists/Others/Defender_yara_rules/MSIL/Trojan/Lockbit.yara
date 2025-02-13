rule Trojan_MSIL_Lockbit_SAD_2147919114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lockbit.SAD!MTB"
        threat_id = "2147919114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 44 69 00 70 0b 73 ?? ?? ?? 0a 0c 08 07 6f bb 00 00 0a 6f bc 00 00 0a 6f ?? ?? ?? 0a 6f be 00 00 0a 0d 09 6f bf 00 00 0a 13 04 11 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

