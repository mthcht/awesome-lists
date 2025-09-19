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

rule TrojanDownloader_Win64_CoinMiner_ARA_2147952566_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/CoinMiner.ARA!MTB"
        threat_id = "2147952566"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 0f b6 09 83 e1 0f 4a 0f be 84 31 a8 a7 01 00 42 8a 8c 31 b8 a7 01 00 4c 2b c8 41 8b 41 fc d3 e8 03 f8 8b c7 49 03 c2 48 03 c6 48 3b d8 72 2b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

