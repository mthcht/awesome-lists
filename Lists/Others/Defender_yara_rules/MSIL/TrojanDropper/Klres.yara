rule TrojanDropper_MSIL_Klres_A_2147832620_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Klres.A!MTB"
        threat_id = "2147832620"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Klres"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 0d 06 28 ?? 00 00 0a 3a ?? 00 00 00 06 28 ?? 00 00 0a 26 07 28 ?? 00 00 0a 39 ?? 00 00 00 ?? ?? ?? ?? ?? [0-5] 28 ?? 00 00 0a 13 04 16 13 05 38 ?? 00 00 00 11 04 11 05 9a 6f ?? 00 00 0a 11 05 17 58 13 05 11 05 11 04 8e 69 3f e5 ff ff ff 08 28 ?? 00 00 0a 39 ?? 00 00 00 08 28 ?? 00 00 0a 08 04 28 ?? 00 00 0a 08 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

