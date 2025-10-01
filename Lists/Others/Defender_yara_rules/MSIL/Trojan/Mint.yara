rule Trojan_MSIL_Mint_SPBX_2147953703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mint.SPBX!MTB"
        threat_id = "2147953703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mint"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 8e b7 18 da 16 da 17 d6 6b 28 ?? 00 00 0a 5a 28 ?? 00 00 0a 22 ?? ?? ?? 3f 58 6b 6c 28 ?? 00 00 0a b7 13 04 08 07 11 04 93 6f ?? 00 00 0a 26 09 17 d6 0d 09 11 05 31 c2}  //weight: 4, accuracy: Low
        $x_1_2 = "zHguegYZhrdPToa" ascii //weight: 1
        $x_1_3 = "JsjngZrrwuRAKvO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

