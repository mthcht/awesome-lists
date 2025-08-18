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

rule Trojan_Win32_Shutdown_PAFV_2147949536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shutdown.PAFV!MTB"
        threat_id = "2147949536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shutdown"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 c8 c1 f8 1f c1 fa 02 29 c2 8d 04 92 8d 04 82 29 c1 8b 45 e0 29 cb 03 5d e4 89 04 24 89 5c 24 04 89 5d e4}  //weight: 2, accuracy: High
        $x_2_2 = "taskkill /f /im explorer.exe" ascii //weight: 2
        $x_2_3 = {73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 66 20 2f 74 20 [0-2] 20 2f 63 20 22}  //weight: 2, accuracy: Low
        $x_1_4 = "APPDATA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

