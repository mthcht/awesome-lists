rule Ransom_Win32_DarkX_YAR_2147978700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DarkX.YAR!MTB"
        threat_id = "2147978700"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "YOUR FILES HAVE BEEN ENCRYPTED!" ascii //weight: 3
        $x_3_2 = "DARKX RANSOMWARE" ascii //weight: 3
        $x_2_3 = "RANSOM:" ascii //weight: 2
        $x_2_4 = "FILE EXTENSION: .darkx" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_DarkX_YAQ_2147978701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DarkX.YAQ!MTB"
        threat_id = "2147978701"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DarkX Ransomware" ascii //weight: 3
        $x_3_2 = "powershell -Command \"Set-MpPreference -DisableBehaviorMonitoring $true\"" ascii //weight: 3
        $x_3_3 = "powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"" ascii //weight: 3
        $x_2_4 = "BITCOIN ADDRESS:" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

