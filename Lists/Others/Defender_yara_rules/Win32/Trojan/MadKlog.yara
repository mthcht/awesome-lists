rule Trojan_Win32_MadKlog_A_2147730057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MadKlog.A!MTB"
        threat_id = "2147730057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MadKlog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REG ADD \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"" ascii //weight: 1
        $x_1_2 = "powershell \"$emailSmtpServer = \\\"smtp.gmail.com\\\";" ascii //weight: 1
        $x_1_3 = "cmd.exe /C ping localhost -n 1 -w 3000 > Nul & Del /f /q \"%s\"" wide //weight: 1
        $x_1_4 = "KeyLogger\\Release\\KeyLogger.pdb" ascii //weight: 1
        $x_1_5 = "KeyPresses.txt" ascii //weight: 1
        $x_1_6 = "Exe is not in appdata" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

