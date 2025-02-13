rule TrojanSpy_MSIL_Rinlogol_A_2147688697_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Rinlogol.A"
        threat_id = "2147688697"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rinlogol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rin Logger ::: {0} ({1})" wide //weight: 1
        $x_1_2 = "Logs Sent!" wide //weight: 1
        $x_1_3 = "Clock Tick!" wide //weight: 1
        $x_1_4 = "user32:SetWindowsHookExA" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

