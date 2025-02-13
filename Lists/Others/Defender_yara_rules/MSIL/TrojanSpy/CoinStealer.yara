rule TrojanSpy_MSIL_CoinStealer_C_2147725084_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/CoinStealer.C!bit"
        threat_id = "2147725084"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinStealer"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BitcoinStealer.exe" ascii //weight: 1
        $x_1_2 = "DeleteItself" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

