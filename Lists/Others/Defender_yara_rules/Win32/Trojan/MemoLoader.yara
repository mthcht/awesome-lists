rule Trojan_Win32_MemoLoader_DA_2147917641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MemoLoader.DA!MTB"
        threat_id = "2147917641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MemoLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
        $x_1_2 = "New-Object -ComObject \"WScript.Shell\"" ascii //weight: 1
        $x_1_3 = "CreateShortcut(\"$env:APPDATA" ascii //weight: 1
        $x_1_4 = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "Powershell.exe -executionPolicy Unrestricted -File" ascii //weight: 1
        $x_1_6 = {43 00 3a 00 5c 00 54 00 65 00 6d 00 70 00 73 00 63 00 72 00 69 00 70 00 74 00 5c 00 [0-15] 2e 00 70 00 73 00 31 00}  //weight: 1, accuracy: Low
        $x_1_7 = {43 3a 5c 54 65 6d 70 73 63 72 69 70 74 5c [0-15] 2e 70 73 31}  //weight: 1, accuracy: Low
        $x_1_8 = "Start-Sleep -s 5" ascii //weight: 1
        $x_1_9 = "Restart-Computer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

