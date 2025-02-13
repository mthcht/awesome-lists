rule Trojan_MSIL_Atraps_SK_2147892982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Atraps.SK!MTB"
        threat_id = "2147892982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Atraps"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 7b 0a 00 00 04 7b 25 00 00 04 07 17 58 0e 04 07 9a 05 6f ?? ?? ?? 06 07 9a 28 ?? ?? ?? 06 6f ?? ?? ?? 06 07 17 58 0b 07 6e 0e 04 8e 69 6a 32 cf}  //weight: 2, accuracy: Low
        $x_2_2 = "BUM.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

