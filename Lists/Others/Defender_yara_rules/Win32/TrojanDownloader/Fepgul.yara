rule TrojanDownloader_Win32_Fepgul_A_2147616671_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fepgul.A"
        threat_id = "2147616671"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fepgul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&op_type=add&submit=ok" wide //weight: 2
        $x_2_2 = "&password=" wide //weight: 2
        $x_2_3 = "user.asp?username=" wide //weight: 2
        $x_2_4 = "c:\\windows\\system\\SkypeClient.exe" wide //weight: 2
        $x_2_5 = "C:\\Program Files\\Skype\\Phone\\keyfile" wide //weight: 2
        $x_1_6 = "taskkill /f /im 360" wide //weight: 1
        $x_1_7 = "cmd /c net stop KAVStart" wide //weight: 1
        $x_1_8 = "cmd /c net stop sharedaccess" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

