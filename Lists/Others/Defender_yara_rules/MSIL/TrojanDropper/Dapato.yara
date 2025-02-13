rule TrojanDropper_MSIL_Dapato_AO_2147839140_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Dapato.AO!MTB"
        threat_id = "2147839140"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 fb 00 00 70 6f ?? ?? ?? 0a 2c 1a 02 72 fb 00 00 70 28 3d 00 00 0a 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

