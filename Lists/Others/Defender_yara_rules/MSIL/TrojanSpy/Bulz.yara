rule TrojanSpy_MSIL_Bulz_UGF_2147832029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Bulz.UGF!MTB"
        threat_id = "2147832029"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 11 04 09 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 0d 00 09 14 fe 03 13 05 11 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Bulz_ABZ_2147850138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Bulz.ABZ!MTB"
        threat_id = "2147850138"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bulz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 fe 01 60 13 04 11 04 2c 12 72 0b 03 00 70 16 14 28 ?? ?? ?? 0a 26 38 cf 00 00 00 00 73 a1 00 00 0a 0a 06 0d 09 72 49 03 00 70 73 a2 00 00 0a 6f ?? ?? ?? 0a 00 09 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

