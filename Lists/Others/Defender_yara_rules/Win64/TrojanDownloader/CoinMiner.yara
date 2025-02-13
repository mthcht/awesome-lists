rule TrojanDownloader_Win64_CoinMiner_S_2147734908_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/CoinMiner.S!bit"
        threat_id = "2147734908"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/nicehash/nheqminer/releases/download/" wide //weight: 1
        $x_1_2 = "\\Windows_x64_nheqminer-5c\\Zcash.exe" wide //weight: 1
        $x_1_3 = "zec-eu1.nanopool.org:" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

