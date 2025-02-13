rule PWS_Win32_Stimilino_2147693440_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Stimilino"
        threat_id = "2147693440"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Stimilino"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "_StealLog.txt" ascii //weight: 2
        $x_1_2 = "\\Steal\\Release\\Steal" ascii //weight: 1
        $x_1_3 = "loginusers.vdf" ascii //weight: 1
        $x_1_4 = "config\\SteamAppData.vdf" ascii //weight: 1
        $x_1_5 = "node0.net2ftp.ru" ascii //weight: 1
        $x_1_6 = "taskkill /f /im Steam.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

