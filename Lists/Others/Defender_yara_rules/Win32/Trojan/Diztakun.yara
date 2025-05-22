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

rule Trojan_Win32_Diztakun_ADI_2147941921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Diztakun.ADI!MTB"
        threat_id = "2147941921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Diztakun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b ca c1 f9 06 83 e2 3f 6b d2 38 8b 0c 8d f8 2b 44 00 88 44 11 29 8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 f8 2b 44 00 8b 45 14 c1 e8 10 32 44 11 2d 24 01 30 44 11 2d}  //weight: 2, accuracy: High
        $x_3_2 = {b9 18 c3 43 00 e8 ?? ?? ?? ?? b9 24 c3 43 00 e8 ?? ?? ?? ?? b9 34 c3 43 00 e8 ?? ?? ?? ?? b9 48 c3 43 00 e8 ?? ?? ?? ?? b9 48 30 44 00 e8 ?? ?? ?? ?? 6a 06 68 48 30 44 00 ff 15 ?? ?? ?? ?? b9 5c c3 43 00}  //weight: 3, accuracy: Low
        $x_1_3 = "Shepard.R_merged\\Release\\Shepard.R_merged.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

