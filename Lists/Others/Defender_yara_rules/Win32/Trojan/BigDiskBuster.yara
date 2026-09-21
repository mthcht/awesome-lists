rule Trojan_Win32_BigDiskBuster_DA_2147978526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BigDiskBuster.DA!MTB"
        threat_id = "2147978526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BigDiskBuster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\" ascii //weight: 1
        $x_1_2 = "ProgramData\\Microsoft\\Windows Defender\\Platform\\" ascii //weight: 1
        $x_1_3 = "Windows\\System32\\MRT.exe" ascii //weight: 1
        $x_1_4 = "NtQueryVolumeInformationFile" ascii //weight: 1
        $x_1_5 = "ReadDirectoryChangesW" ascii //weight: 1
        $x_1_6 = "SetFileInformationByHandle" ascii //weight: 1
        $x_1_7 = "Disk buster file :" ascii //weight: 1
        $x_1_8 = "BigDiskBuster" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

