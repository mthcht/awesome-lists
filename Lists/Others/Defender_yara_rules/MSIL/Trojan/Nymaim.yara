rule Trojan_MSIL_Nymaim_NB_2147902549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nymaim.NB!MTB"
        threat_id = "2147902549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nymaim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e ?? 19 00 04 0e 06 17 59 e0 95 58 0e 05 28 ?? 43 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

