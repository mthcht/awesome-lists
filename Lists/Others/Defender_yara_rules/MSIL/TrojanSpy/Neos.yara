rule TrojanSpy_MSIL_Neos_A_2147653906_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Neos.A"
        threat_id = "2147653906"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Neos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SkyNeos V1.0 Keylogger Engine Started Successfully!" wide //weight: 1
        $x_1_2 = "Victim Computer Name:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

