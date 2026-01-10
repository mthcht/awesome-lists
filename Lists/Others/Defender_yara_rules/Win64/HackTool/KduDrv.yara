rule HackTool_Win64_KduDrv_DA_2147960931_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/KduDrv.DA!MTB"
        threat_id = "2147960931"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "KduDrv"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kernelmoduleunloader.exe" ascii //weight: 1
        $x_1_2 = "\\KduPort" ascii //weight: 1
        $x_1_3 = "-drvn" ascii //weight: 1
        $x_1_4 = "-drvr" ascii //weight: 1
        $x_1_5 = "\\BaseNamedObjects\\%ws" ascii //weight: 1
        $x_1_6 = "Gmer 'Antirootkit'" ascii //weight: 1
        $x_1_7 = "gmerdrv" ascii //weight: 1
        $x_1_8 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%ws" ascii //weight: 1
        $x_1_9 = "\\KnownDlls\\kernel32.dll" ascii //weight: 1
        $x_1_10 = "Mimikatz mimidrv" ascii //weight: 1
        $x_1_11 = "Shellcode support mask: 0x%08x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

