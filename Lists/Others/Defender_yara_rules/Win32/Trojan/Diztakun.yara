rule Trojan_Win32_Diztakun_AR_2147752855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Diztakun.AR!MTB"
        threat_id = "2147752855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Diztakun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "taskkill /f /im explorer.exe" ascii //weight: 10
        $x_5_2 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f" ascii //weight: 5
        $x_10_3 = "echo CORONAVIRUS" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

