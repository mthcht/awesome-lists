rule TrojanDownloader_Win32_Coins_BBX_2147826590_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Coins.BBX!MTB"
        threat_id = "2147826590"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 48 18 fd 43 03 00 81 c1 c3 9e 26 00 89 48 18 c1 e9 10 81 e1 ff 7f 00 00 8b c1 c3}  //weight: 1, accuracy: High
        $x_1_2 = {50 68 80 00 00 00 6a 02 50 50 68 00 00 00 40 57 8a d8 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {d1 e9 8b d1 81 f2 20 83 b8 ed 24 01 0f 44 d1 83 eb 01}  //weight: 1, accuracy: High
        $x_1_4 = "fw3.exe" wide //weight: 1
        $x_1_5 = "fw%d.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Coins_GCW_2147838545_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Coins.GCW!MTB"
        threat_id = "2147838545"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 09 03 c1 89 45 fc 8b 45 08 40 89 45 08 8b 45 fc 25 00 00 00 f0 89 45 f8 74 ?? 8b 45 f8 c1 e8 18 33 45 fc 89 45 fc 8b 45 f8 f7 d0 23 45 fc 89 45 fc}  //weight: 10, accuracy: Low
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 63 00 73 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "/c \"powershell -command IEX(New-Object Net.Webclient).DownloadString('%s/%s')\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

