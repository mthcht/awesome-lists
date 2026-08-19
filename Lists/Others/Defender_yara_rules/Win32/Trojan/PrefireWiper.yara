rule Trojan_Win32_PrefireWiper_MKZ_2147976460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PrefireWiper.MKZ!MTB"
        threat_id = "2147976460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PrefireWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DisableRealtimeMonitoring /t REG_DWORD" ascii //weight: 3
        $x_3_2 = "vssadmin delete shadows /all /quiet 2>nul" ascii //weight: 3
        $x_2_3 = "taskkill /f /im" ascii //weight: 2
        $x_2_4 = ".locked" ascii //weight: 2
        $x_1_5 = "reg delete" ascii //weight: 1
        $x_1_6 = "REG_SZ /d \"shutdown /r /f /t" ascii //weight: 1
        $x_1_7 = "cmd /c del /f /q" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

