rule Trojan_Win32_FireStream_A_2147963986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FireStream.A!dha"
        threat_id = "2147963986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FireStream"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /create /tn {} /tr \"{}\" /sc {} /mo {} /ru {} /f" ascii //weight: 1
        $x_1_2 = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\" /v \"SetupExecute\"" ascii //weight: 1
        $x_1_3 = "shutdown /r /f /t 0" ascii //weight: 1
        $x_1_4 = "failed to create scheduled task" ascii //weight: 1
        $x_1_5 = "failed to write registry keys" ascii //weight: 1
        $x_1_6 = "failed to write file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

