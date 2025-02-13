rule TrojanDownloader_PowerShell_CoinMiner_A_2147725301_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/CoinMiner.A"
        threat_id = "2147725301"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".downloadstring('http://p.estonine.com" wide //weight: 1
        $x_1_2 = ".downloadstring('http://cdn.chatcdn.net" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

