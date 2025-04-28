rule Trojan_Win32_QuasarRAT_A_2147893085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QuasarRAT.A!MTB"
        threat_id = "2147893085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f4 8b 44 85 d0 89 45 ec 8b 45 ec 89 04 24 e8 ?? ?? ?? ?? 89 45 e8 8d 45 cc 89 44 24 08 8b 45 e8 89 44 24 04 8b 45 ec 89 04 24 e8 ?? ?? ?? ?? 89 45 e4 83 7d e4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QuasarRAT_AYA_2147940213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QuasarRAT.AYA!MTB"
        threat_id = "2147940213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QuasarRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "141.98.7.51/stub/Shell.exe" ascii //weight: 2
        $x_1_2 = "XWORM NOT FIXED" ascii //weight: 1
        $x_1_3 = "powershell -inputformat none -outputformat none -NonInteractive -Command" ascii //weight: 1
        $x_1_4 = "Add-MpPreference -ExclusionPath C:\\Windows\\PowerShell" ascii //weight: 1
        $x_1_5 = "Injection completed!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

