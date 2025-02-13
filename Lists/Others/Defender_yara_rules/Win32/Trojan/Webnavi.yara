rule Trojan_Win32_Webnavi_A_2147642062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Webnavi.A"
        threat_id = "2147642062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Webnavi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\windows\\system32\\once.exe" ascii //weight: 1
        $x_1_2 = "\\windows\\system32\\qq.ico" ascii //weight: 1
        $x_1_3 = "/once.htm?" ascii //weight: 1
        $x_1_4 = "\\[MAINURL:(.*?)\\]" ascii //weight: 1
        $x_1_5 = "www.baidu.com/s?word=%s&ie=utf-8&tn=laiyiba_" ascii //weight: 1
        $x_1_6 = "www.hao123.cn/?ie" ascii //weight: 1
        $x_1_7 = ":\\windows\\system32\\oemlinkicon.ico" ascii //weight: 1
        $x_1_8 = {48 61 6f 31 32 33 cd f8 d6 b7 b5 bc ba bd 00}  //weight: 1, accuracy: High
        $x_1_9 = "\"sureh\" \"QQ.exe\"" ascii //weight: 1
        $x_1_10 = "http://d.laiyiba.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Webnavi_C_2147644380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Webnavi.C"
        threat_id = "2147644380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Webnavi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Policies\\Explorer /v NoInternetIcon /t REG_DWORD /d 00000001 /f" ascii //weight: 1
        $x_1_2 = "copy /Y \"%myfiles%\\lnternet Explorer.lnk\" \"C:\\Documents and Settings\\All Users\\" ascii //weight: 1
        $x_1_3 = "//www.789dh.com" wide //weight: 1
        $x_1_4 = "echo y|cacls.exe c:\\docume~1\\alluse~1\\" ascii //weight: 1
        $x_1_5 = "quickl~1\\lntern~1.lnk /p everyone:r >nul 1>nul" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

