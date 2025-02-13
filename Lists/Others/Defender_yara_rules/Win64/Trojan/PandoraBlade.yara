rule Trojan_Win64_PandoraBlade_B_2147813515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PandoraBlade.B!dha"
        threat_id = "2147813515"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PandoraBlade"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command Add-MpPreference -ExclusionPath" ascii //weight: 1
        $x_1_2 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\cvtres.exe" ascii //weight: 1
        $x_1_3 = "Pandora hVNC" ascii //weight: 1
        $x_1_4 = "Pandora WILL NOT be installed to your system" ascii //weight: 1
        $x_1_5 = "DelegateWriteProcessMemory" ascii //weight: 1
        $x_1_6 = "explorer.exe" ascii //weight: 1
        $x_1_7 = "VirtualAllocEx" ascii //weight: 1
        $x_1_8 = "CreateProcessA" ascii //weight: 1
        $x_1_9 = "RunPE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

