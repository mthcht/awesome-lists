rule Trojan_Win32_ZloaderTeams_A_2147767186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZloaderTeams.A!ibt"
        threat_id = "2147767186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZloaderTeams"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell -command Import-Module BitsTransfer; Start-BitsTransfer -Source" wide //weight: 10
        $x_1_2 = "https://" wide //weight: 1
        $x_1_3 = "Unblock-File" wide //weight: 1
        $x_1_4 = "Start-Process" wide //weight: 1
        $x_2_5 = "hidcon:cmd /c echo HTcoX & start Teams_windows_x64.exe" wide //weight: 2
        $x_2_6 = "hidcon:forcenowait:cmd /c certreq -post -config http" wide //weight: 2
        $x_2_7 = "hidcon:cmd /c if not %computername%" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

