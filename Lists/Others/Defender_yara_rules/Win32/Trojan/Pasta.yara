rule Trojan_Win32_Pasta_ASL_2147912365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pasta.ASL!MTB"
        threat_id = "2147912365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pasta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dhku.com" wide //weight: 1
        $x_1_2 = "www.212ok.com/Gbook.asp?qita" wide //weight: 1
        $x_1_3 = "/P users:R" wide //weight: 1
        $x_1_4 = "C:\\Program Files\\Internet Explorer\\iexplore.exe http://www.ymtuku.com/xg/?tan" wide //weight: 1
        $x_1_5 = "{A0XC6A98-A14C-J35H-46UD-F5AR862J2AH5}" wide //weight: 1
        $x_1_6 = "C:\\WINDOWS\\system32\\qx.bat" wide //weight: 1
        $x_1_7 = "\\system32\\aoyou.bat" wide //weight: 1
        $x_1_8 = "C:\\WINDOWS\\windows.exe" wide //weight: 1
        $x_1_9 = "c:\\system.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

