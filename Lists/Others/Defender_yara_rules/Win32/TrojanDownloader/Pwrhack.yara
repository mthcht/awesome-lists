rule TrojanDownloader_Win32_Pwrhack_A_2147597207_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pwrhack.A"
        threat_id = "2147597207"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pwrhack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lec.nevysearch.com/process/use_cnt.php?mac=AA-AA-AA-AA-AA-AA" ascii //weight: 1
        $x_1_2 = "up1.adlay.net" ascii //weight: 1
        $x_1_3 = "PowerHacker_Charm.dll" ascii //weight: 1
        $x_1_4 = "PowerHacker.ini" ascii //weight: 1
        $x_1_5 = "Winspss.exe" ascii //weight: 1
        $x_1_6 = "psjm.dll" ascii //weight: 1
        $x_1_7 = "\\system32\\regsvr32.exe /s psjm.dll" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

