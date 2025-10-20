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

rule TrojanDownloader_Win64_CoinMiner_PZM_2147955527_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/CoinMiner.PZM!MTB"
        threat_id = "2147955527"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 8d 85 c0 00 00 00 48 8d 0d ?? ?? 00 00 48 89 c2 e8 ?? ?? ?? ?? 48 8d 45 b0 48 8d 0d ?? ?? 00 00 48 89 c2 e8 ?? ?? ?? ?? 48 8d 95 c0 00 00 00 48 8d 05 ?? ?? 00 00 c7 44 24 28 01 00 00 00 48 c7 44 24 ?? 00 00 00 00 41 b9 00 00 00 00 49 89 d0 48 89 c2 b9 00 00 00 00 48 8b 05 ?? ?? 00 00 ff d0}  //weight: 4, accuracy: Low
        $x_1_2 = "loader_miner/start.exe" ascii //weight: 1
        $x_1_3 = "loader_miner/updateChrome.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

