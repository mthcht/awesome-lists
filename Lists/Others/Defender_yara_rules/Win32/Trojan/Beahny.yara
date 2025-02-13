rule Trojan_Win32_Beahny_A_2147735020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Beahny.A"
        threat_id = "2147735020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Beahny"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "del /f /q \"%s\" cmd /c start /b  /ru system /sc @echo off" ascii //weight: 1
        $x_1_2 = "&schtasks /Windows Server 2etconnectionid!=le|findstr RUNNIGetNativeSy" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "C:\\\\windows\\temp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

