rule Trojan_MSIL_DInvoke_KAA_2147902503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DInvoke.KAA!MTB"
        threat_id = "2147902503"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DInvoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 1a 5d 1e 5a 1f 1f 5f 63 61 d1 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

