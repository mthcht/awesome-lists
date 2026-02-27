rule Trojan_MSIL_UltimateStealer_AMTB_2147963765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/UltimateStealer!AMTB"
        threat_id = "2147963765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "UltimateStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UltimateStealer.Program+<CheckLiveBankSessions>" ascii //weight: 1
        $x_1_2 = "UltimateStealer.Program+<SendPhishingLink>" ascii //weight: 1
        $x_1_3 = "UltimateStealer.Program+<StealTONWallet>" ascii //weight: 1
        $x_1_4 = "UltimateStealer.Program+<StealDesktopWallets>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

