rule TrojanSpy_MSIL_Sorano_A_2147752337_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Sorano.A!MTB"
        threat_id = "2147752337"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sorano"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT * FROM AntivirusProduct" wide //weight: 1
        $x_1_2 = "\\AutoFill.txt" wide //weight: 1
        $x_1_3 = "\\Browsers\\Passwords.txt" wide //weight: 1
        $x_1_4 = "\\BitcoinCore\\wallet.dat" wide //weight: 1
        $x_1_5 = "http://fuckingav.xyz/antivirus.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

