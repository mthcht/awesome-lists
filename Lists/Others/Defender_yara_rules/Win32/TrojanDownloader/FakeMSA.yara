rule TrojanDownloader_Win32_FakeMSA_A_2147596301_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/FakeMSA.gen!A"
        threat_id = "2147596301"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeMSA"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "90"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "URLDownloadToFileA" ascii //weight: 20
        $x_20_2 = "ShellExecuteA" ascii //weight: 20
        $x_20_3 = "VBA6.DLL" ascii //weight: 20
        $x_20_4 = "EVENT_SINK_QueryInterface" ascii //weight: 20
        $x_5_5 = "Microsoft Security Adviser" wide //weight: 5
        $x_5_6 = "/out.php" wide //weight: 5
        $x_5_7 = "dwnldr.exe" wide //weight: 5
        $x_5_8 = "AntivirXP08" wide //weight: 5
        $x_5_9 = "mssadv" wide //weight: 5
        $x_5_10 = "msctrl" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 6 of ($x_5_*))) or
            ((4 of ($x_20_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_FakeMSA_B_2147597960_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/FakeMSA.gen!B"
        threat_id = "2147597960"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeMSA"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Security Adviser" wide //weight: 1
        $x_1_2 = "webbrowser3.exe" wide //weight: 1
        $x_1_3 = "yourthumbnails.com/?id=" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "InternetReadFile" ascii //weight: 1
        $x_1_6 = "HttpOpenRequestA" ascii //weight: 1
        $x_1_7 = "FtpPutFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

