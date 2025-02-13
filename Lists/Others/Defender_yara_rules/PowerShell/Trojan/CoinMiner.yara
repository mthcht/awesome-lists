rule Trojan_PowerShell_CoinMiner_A_2147725300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/CoinMiner.A"
        threat_id = "2147725300"
        type = "Trojan"
        platform = "PowerShell: "
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc IEX (New-Object Net.WebClient).DownloadString(" wide //weight: 1
        $x_1_2 = {49 00 45 00 58 00 20 00 28 00 4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 35 00 2e 00 32 00 30 00 34 00 2e 00 37 00 34 00 2e 00 31 00 30 00 35 00 2f 00 [0-255] 2e 00 63 00 73 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

