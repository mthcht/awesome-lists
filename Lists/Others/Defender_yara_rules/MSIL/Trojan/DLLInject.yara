rule Trojan_MSIL_DLLInject_PSWA_2147888882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DLLInject.PSWA!MTB"
        threat_id = "2147888882"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DLLInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 3a 04 00 00 16 06 6f ?? 00 00 0a 28 ?? 00 00 06 72 b7 02 00 70 28 ?? 00 00 06 72 d1 02 00 70 28 ?? 00 00 06 0c 25 7e 27 00 00 0a 07 6f ?? 00 00 0a 17 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

