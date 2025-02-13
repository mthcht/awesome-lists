rule Backdoor_Win32_Olux_A_2147619307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Olux.A"
        threat_id = "2147619307"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Olux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "del %s" ascii //weight: 10
        $x_10_2 = "%sas32.bat" ascii //weight: 10
        $x_10_3 = "%sder32.exe" ascii //weight: 10
        $x_10_4 = "!PARANOID!" ascii //weight: 10
        $x_10_5 = "%s?uin=%d" ascii //weight: 10
        $x_10_6 = "taskkill /f /pid %d " ascii //weight: 10
        $x_1_7 = "\\msauc.exe" ascii //weight: 1
        $x_1_8 = "lsass driver" ascii //weight: 1
        $x_1_9 = "login.icq.com" ascii //weight: 1
        $x_1_10 = "GET %s HTTP/1.1" ascii //weight: 1
        $x_1_11 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 5 of ($x_1_*))) or
            ((6 of ($x_10_*))) or
            (all of ($x*))
        )
}

