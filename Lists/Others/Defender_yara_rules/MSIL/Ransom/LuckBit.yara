rule Ransom_MSIL_LuckBit_MA_2147893229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LuckBit.MA!MTB"
        threat_id = "2147893229"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LuckBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 6f 47 00 00 0a 1e 5b 1f 0b 59 8d ?? 00 00 01 0d 2b 1b 06 09 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 04 08 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 07 09 16 09 8e 69 6f ?? ?? ?? 0a 16 30 d7 de 1e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

