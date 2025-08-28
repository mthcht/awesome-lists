rule Backdoor_MSIL_Blakken_AUDB_2147950631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Blakken.AUDB!MTB"
        threat_id = "2147950631"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blakken"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 06 28 ?? 00 00 0a 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 14 13 04 38 ?? 00 00 00 00 73 ?? 00 00 0a 13 05 11 05 20 ?? ?? 00 00 28 ?? ?? 00 06 73 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06 73 ?? 00 00 0a 13 07 11 06 11 07 6f ?? 00 00 0a 11 07 6f ?? 00 00 0a 13 04 de 0c}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

