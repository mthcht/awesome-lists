rule TrojanDownloader_Win32_Pasoban_A_2147695706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pasoban.A"
        threat_id = "2147695706"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pasoban"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MorshIBA" ascii //weight: 1
        $x_1_2 = "PLoKahttp" ascii //weight: 1
        $x_1_3 = "\\WindowsUpdate.exe" wide //weight: 1
        $x_1_4 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\" /v \"1806\" /t REG_DWORD /d 0 /f" wide //weight: 1
        $x_1_5 = "xiquepaisucxzas.exe" ascii //weight: 1
        $x_1_6 = "balwonsa.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

