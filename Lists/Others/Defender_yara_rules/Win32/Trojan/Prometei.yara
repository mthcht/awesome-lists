rule Trojan_Win32_Prometei_CCIR_2147936494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Prometei.CCIR!MTB"
        threat_id = "2147936494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Prometei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d9 02 da 30 18 85 c9 74 ?? 40 8d 98 ?? ?? ?? ?? 49 03 d7 3b de 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Prometei_APR_2147936605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Prometei.APR!MTB"
        threat_id = "2147936605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Prometei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 15 ce 7e d0 00 c6 05 d0 7e d0 00 73 c6 05 d1 7e d0 00 65 a2 d2 7e d0 00 c6 05 d3 7e d0 00 75 88 15 d4 7e d0 00 c6 05 d5 7e d0 00 5f 88 0d d6 7e d0 00 c6 05 d7 7e d0 00 69 a2 d8 7e d0 00 c6 05 d9 7e d0 00 6c c6 05 da 7e d0 00 6f 88 0d db 7e d0 00 c6 05 dc 7e d0 00 2e a2 dd 7e d0 00 c6 05 de 7e d0 00 78 a2 df 7e d0 00 c6 05 e0 7e d0 00 00 c7 45 fc 00 00 00 00 ff 15}  //weight: 2, accuracy: High
        $x_1_2 = {8a da 02 d9 30 18 85 c9 74 ?? 40 8d 98 eb ea ea ea 49 03 d7 3b de}  //weight: 1, accuracy: Low
        $x_5_3 = "netsh advfirewall firewall delete rule name=\"Banned brute IPs\"" ascii //weight: 5
        $x_4_4 = "Auditpol /set /subcategory:\"Logon\" /failure:enable" ascii //weight: 4
        $x_3_5 = "temp\\setup_gitlog.txt" wide //weight: 3
        $x_1_6 = "sqhost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Prometei_AHC_2147951552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Prometei.AHC!MTB"
        threat_id = "2147951552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Prometei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8a 4d fc 02 c8 30 0f 3b c3 74 ?? 8b 4d f8 48 01 4d fc 47 8d 8f ?? ?? ?? ?? 3b ce 7c}  //weight: 20, accuracy: Low
        $x_30_2 = {c6 45 de 6c c6 45 df 69 c6 45 e0 64 c6 45 e1 20 c6 45 e2 63 c6 45 e3 6f 88 5d e4 89 5d ec}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Prometei_ABVS_2147966297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Prometei..ABVS!MTB"
        threat_id = "2147966297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Prometei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c6 85 05 ff ff ff 77 c6 85 06 ff ff ff 63 c6 85 07 ff ff ff 5a c6 85 08 ff ff ff 44 c6 85 09 ff ff ff 78 c6 85 0a ff ff ff 46 c6 85 0b ff ff ff 71 c6 85 0c ff ff ff 41 c6 85 0d ff ff ff 53 c6 85 0e ff ff ff 45 c6 85 0f ff ff ff 4a c6 85 10 ff ff ff 54 c6 85 11 ff ff ff 4f c6 85 12 ff ff ff 43 c6 85 13 ff ff ff 72}  //weight: 5, accuracy: High
        $x_1_2 = "powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath \"C:\\Windows\\Dell" ascii //weight: 1
        $x_1_3 = "[System.Convert]::FromBase64String" ascii //weight: 1
        $x_1_4 = {2f 43 20 72 65 6e 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 64 65 6c 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "45.87.174.8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

