rule Trojan_MSIL_Mikey_ND_2147916580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mikey.ND!MTB"
        threat_id = "2147916580"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 02 06 91 03 06 ?? ?? 00 00 0a 61 d2 9c 06 17 58 0a 06 02 8e 69}  //weight: 5, accuracy: Low
        $x_1_2 = "-- BUILD:" ascii //weight: 1
        $x_1_3 = "OpenProcess" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

