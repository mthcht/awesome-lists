rule Ransom_Win64_Recon_VGX_2147967061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Recon.VGX!MTB"
        threat_id = "2147967061"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Recon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /Create /SC ONLOGON /RL HIGHEST /F /TN \"SysCore\" /TR" ascii //weight: 1
        $x_1_2 = "vssadmin" ascii //weight: 1
        $x_1_3 = "shadowcopy" ascii //weight: 1
        $x_1_4 = "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f" ascii //weight: 1
        $x_1_5 = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\" /v TamperProtection /t REG_DWORD /d 0 /f" ascii //weight: 1
        $x_1_6 = "Files encrypted! Read C:\\README_DECRYPT.txt" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Sandbox\\" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_9 = "Software\\Classes\\ms-settings\\shell\\open\\command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

