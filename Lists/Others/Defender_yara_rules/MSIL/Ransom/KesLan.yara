rule Ransom_MSIL_KesLan_G_2147745593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/KesLan.G!MTB"
        threat_id = "2147745593"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KesLan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 09 11 04 09 6f ?? ?? ?? ?? 1e 5b 6f ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 09 11 04 09 6f ?? ?? ?? ?? 1e 5b 6f ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 09 17 6f ?? ?? ?? ?? 00 08 09 6f ?? ?? ?? ?? 17 73 ?? ?? ?? ?? 13 05}  //weight: 1, accuracy: Low
        $x_1_2 = "BTC(Bitcoin) Address:" ascii //weight: 1
        $x_1_3 = "Ben:  Kes Lan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

