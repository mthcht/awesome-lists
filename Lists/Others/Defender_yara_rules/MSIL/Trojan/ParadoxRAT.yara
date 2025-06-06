rule Trojan_MSIL_ParadoxRAT_APR_2147942922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ParadoxRAT.APR!MTB"
        threat_id = "2147942922"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ParadoxRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2c 35 02 7b ?? 00 00 04 06 9a 6f ?? 00 00 0a 2c 0e 02 7b ?? 00 00 04 06 9a 16 6f ?? 00 00 0a 02 7b ?? 00 00 04 06 9a 6f ?? 00 00 0a 02 7b ?? 00 00 04 06 14 a2 2b 05}  //weight: 3, accuracy: Low
        $x_2_2 = {0d 16 0c 2b 65 09 08 9a 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 02 16 28 ?? 00 00 0a 16 33 48 06 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

