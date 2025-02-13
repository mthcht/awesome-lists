rule TrojanSpy_MSIL_PhemedroneStealer_SK_2147918593_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/PhemedroneStealer.SK!MTB"
        threat_id = "2147918593"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhemedroneStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe 0e 03 00 fe 0c 03 00 61 d1 fe 0e 04 00 fe 0c 01 00 fe 0c 04 00}  //weight: 2, accuracy: High
        $x_2_2 = "system.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

