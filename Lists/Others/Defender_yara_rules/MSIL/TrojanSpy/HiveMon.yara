rule TrojanSpy_MSIL_HiveMon_AHV_2147850003_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/HiveMon.AHV!MTB"
        threat_id = "2147850003"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiveMon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 25 17 11 0b a2 25 18 16 8c ?? 00 00 01 a2 6f ?? ?? ?? 0a 26 00 de 0d 11 0a 2c 08 11 0a 6f ?? ?? ?? 0a 00 dc 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

