rule TrojanDownloader_Win32_Conhook_AD_2147596491_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Conhook.AD"
        threat_id = "2147596491"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KerioPersonalFirewallServer" ascii //weight: 1
        $x_1_2 = "outpost.exe" ascii //weight: 1
        $x_1_3 = "zlclient.exe" ascii //weight: 1
        $x_1_4 = "smc.exe" ascii //weight: 1
        $x_1_5 = "fwsrv.exe" ascii //weight: 1
        $x_1_6 = "DuncanMutex" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\DInf" ascii //weight: 1
        $x_1_8 = "{F7EE3DF8-A9D0-47f2-9494-4DDE0B2F0475}" ascii //weight: 1
        $x_1_9 = "\\shell\\open\\command" ascii //weight: 1
        $x_1_10 = "83.149.75.54/cgi-bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Conhook_AE_2147598011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Conhook.AE"
        threat_id = "2147598011"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "58"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://xsearchz.com/script.php?q=%s&cid=%S&aid=%S&version=%S" wide //weight: 1
        $x_1_2 = "http://xsearchz.com/script.php" ascii //weight: 1
        $x_1_3 = "http://65.243.103.62/go/?cmp=vmtek_alexvs&lid=%s&uid=%s&guid=%s" ascii //weight: 1
        $x_1_4 = "Global\\vmc_term" ascii //weight: 1
        $x_1_5 = "explorer.exe" ascii //weight: 1
        $x_1_6 = "services.exe" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" ascii //weight: 1
        $x_1_9 = "rundll32.exe \"%s\",B" ascii //weight: 1
        $x_50_10 = "LoadAppInit_DLLs" ascii //weight: 50
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Conhook_AF_2147610836_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Conhook.AF"
        threat_id = "2147610836"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 45 54 00 25 73 3f 61 3d 25 73 26 74 3d 25 73 26 66 3d 25 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 73 5f 5f 63 30 30 25 58 2e 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {8a 01 3c 30 7c 11 3c 7a 7f 0d 3c 61 0f be c0 7c 03 83 e8 20 88 06 46 41 ff 4d f8 75 e3 ff 75 f4 ff 15 ?? ?? ?? 10 8d 45 fc}  //weight: 1, accuracy: Low
        $x_1_4 = {83 65 fc 00 68 ?? ?? 00 10 68 ?? ?? 00 10 ff 15 ?? ?? 00 10 50 ff 15 ?? ?? 00 10 85 c0 75 02 c9 c3 8d 4d fc 51 6a 00 6a 01 6a 14 ff d0}  //weight: 1, accuracy: Low
        $x_2_5 = {74 29 68 f4 01 00 00 ff d6 55 57 e8 ?? ?? ff ff 85 c0 74 0c 53 ff d6 e8 ?? ?? 00 00 84 c0 75 1d 83 7c 24 10 03 77 09 ff 44 24 10 53 ff d6 eb c1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Conhook_AG_2147618625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Conhook.AG"
        threat_id = "2147618625"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Conhook"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "61AD6207C10D33E6D57CE297" wide //weight: 1
        $x_1_2 = "C7B1B5E46711E40573603574" wide //weight: 1
        $x_1_3 = "BITS" ascii //weight: 1
        $x_1_4 = "xnetini.kdd" wide //weight: 1
        $x_2_5 = {47 47 25 ff 00 ff ff 33 45 0c 66 89 04 56 42 43 83 fb 04 7c 02}  //weight: 2, accuracy: High
        $x_1_6 = {47 32 45 0f 88 04 32 42 43 83 fb 04 7c 02 33 db 47 80 3f 00 75 ?? c6 04 32 00}  //weight: 1, accuracy: Low
        $x_1_7 = {88 45 08 e8 ?? ?? 00 00 8b 35 ?? ?? 01 10 fe c0 53 88 45 09 8d 45 f4 50 6a 02 8d 45 08 50 57 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

