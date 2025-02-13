rule TrojanSpy_MSIL_Joakil_A_2147692195_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Joakil.A"
        threat_id = "2147692195"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Joakil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jklVersion" wide //weight: 1
        $x_1_2 = "screencap" wide //weight: 1
        $x_1_3 = "\\Bitcoin\\wallet.dat" wide //weight: 1
        $x_1_4 = "Shutdown(Global) -" wide //weight: 1
        $x_1_5 = "Failed to setup camera..." wide //weight: 1
        $x_1_6 = "HKEY_CURRENT_USER\\software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Joakil_B_2147705612_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Joakil.B"
        threat_id = "2147705612"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Joakil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jklVersion" wide //weight: 1
        $x_1_2 = "screencap" wide //weight: 1
        $x_1_3 = "Shutdown(Global) -" wide //weight: 1
        $x_1_4 = "HKEY_CURRENT_USER\\software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "- BTCW -From[" wide //weight: 1
        $x_1_6 = "<br>BankLabel:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

