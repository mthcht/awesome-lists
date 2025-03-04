rule Trojan_MSIL_Genkryptik_UYRE_2147808173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Genkryptik.UYRE!MTB"
        threat_id = "2147808173"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Genkryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 02 26 16 02 73 1b 00 00 0a 0a 06 28 ?? ?? ?? 06 0b dd 0d 00 00 00 06 39 06 00 00 00 06 28 ?? ?? ?? 06 dc 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

