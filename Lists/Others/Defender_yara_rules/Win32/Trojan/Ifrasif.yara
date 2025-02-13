rule Trojan_Win32_Ifrasif_A_2147611778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ifrasif.A"
        threat_id = "2147611778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ifrasif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\WINDOWS\\system32\\reg.exe delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v mssysif /f" ascii //weight: 10
        $x_10_2 = "reg.exe add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /t REG_SZ" ascii //weight: 10
        $x_10_3 = "window.status='Done';document.write('<iframe  id=" ascii //weight: 10
        $x_1_4 = "Ifframer thread stop" ascii //weight: 1
        $x_1_5 = "<script>function v(.*)1793A6E6F6E65273E3C2F696672616D653E" ascii //weight: 1
        $x_1_6 = "FtpGetFileA" ascii //weight: 1
        $x_1_7 = "InternetFindNextFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

