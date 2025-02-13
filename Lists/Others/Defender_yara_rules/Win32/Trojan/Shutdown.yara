rule Trojan_Win32_Shutdown_T_2147639035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shutdown.T"
        threat_id = "2147639035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shutdown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "copy virus.bat C:\\windows\\" ascii //weight: 2
        $x_2_2 = "net user roc13" ascii //weight: 2
        $x_2_3 = "mkdir %userprofile%\\desktop\\virus3000" ascii //weight: 2
        $x_2_4 = "shutdown -rThe best hamburger image.png.bat" ascii //weight: 2
        $x_2_5 = "echo A VIRUS HAS BEEN DETECTED ON YOUR COMPUTER AND WILL ERASE EVERYTHING!" ascii //weight: 2
        $x_1_6 = "start iexplore.exe www." ascii //weight: 1
        $x_1_7 = "reg add HKEY_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

