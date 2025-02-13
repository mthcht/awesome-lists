rule Trojan_MSIL_RegRun_ANOH_2147833820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RegRun.ANOH!MTB"
        threat_id = "2147833820"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RegRun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 06 72 01 00 00 70 28 ?? ?? ?? 0a 13 05 06 11 04 11 05 a2 07 11 05 11 04 d2 6f ?? ?? ?? 0a 07 11 05 6f ?? ?? ?? 0a 11 04 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

