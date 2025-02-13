rule TrojanDownloader_Win32_Fiansrch_A_2147596321_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fiansrch.A"
        threat_id = "2147596321"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fiansrch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "godown.geopia.com/Fian/FianSearch7/fianfxmsgs.dll" ascii //weight: 10
        $x_10_2 = "godown.geopia.com/Fian/FianSearch7/FianSearch.exe" ascii //weight: 10
        $x_10_3 = "godown.geopia.com/Fian/FianSearch7/fianUpdateVer.dat" ascii //weight: 10
        $x_10_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\fxmsgsUninst" ascii //weight: 10
        $x_1_5 = "InternetCloseHandle" ascii //weight: 1
        $x_1_6 = "InternetReadFile" ascii //weight: 1
        $x_1_7 = "InternetWriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Fiansrch_B_2147600532_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fiansrch.B"
        threat_id = "2147600532"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fiansrch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "FianSearch.exe" ascii //weight: 1
        $x_1_3 = "fianfxmsgs.dll" ascii //weight: 1
        $x_1_4 = "fzmsgsupdate.exe" ascii //weight: 1
        $x_1_5 = "fsearch.fian.co.kr" ascii //weight: 1
        $x_1_6 = "EAB7AA01-CAAA-4C34-8343-557C7E63B73B" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_9 = "CreateMutexA" ascii //weight: 1
        $x_1_10 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_11 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

