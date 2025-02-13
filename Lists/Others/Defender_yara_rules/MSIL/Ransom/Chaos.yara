rule Ransom_MSIL_Chaos_AFF_2147832253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Chaos.AFF!MTB"
        threat_id = "2147832253"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chaos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 09 0e 04 6f ?? ?? ?? 0a 26 09 0e 05 6f ?? ?? ?? 0a 26 09 0e 06 8c 28 00 00 01 6f ?? ?? ?? 0a 26 02 50 28 ?? ?? ?? 0a 13 04 11 04 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

