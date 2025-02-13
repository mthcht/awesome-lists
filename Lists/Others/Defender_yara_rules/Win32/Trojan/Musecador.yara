rule Trojan_Win32_Musecador_V_2147739942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Musecador.V!MTB"
        threat_id = "2147739942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Musecador"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\123.bat" wide //weight: 1
        $x_1_2 = "reg add \"hklm\\software\\microsoft\\windows nt\\currentversion\\Image File Execution Options\\ZhuDongFangYu.exe\" /v debugger /t reg_sz /d \"ntsd -d\" /f" ascii //weight: 1
        $x_1_3 = "reg add \"hklm\\software\\microsoft\\windows nt\\currentversion\\Image File Execution Options\\360tray.exe\" /v debugger /t reg_sz /d \"ntsd -d\" /f" ascii //weight: 1
        $x_1_4 = "reg add \"hklm\\software\\microsoft\\windows nt\\currentversion\\Image File Execution Options\\taskmgr.exe\" /v debugger /t reg_sz /d \"ntsd -d\" /f" ascii //weight: 1
        $x_1_5 = "cmd.exe /c assoc .txt = exefile" wide //weight: 1
        $x_1_6 = "virus QQ 621370902" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

