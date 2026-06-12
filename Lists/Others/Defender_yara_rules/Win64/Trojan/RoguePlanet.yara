rule Trojan_Win64_RoguePlanet_DA_2147971326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RoguePlanet.DA!MTB"
        threat_id = "2147971326"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RoguePlanet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "64"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "\\\\.\\pipe\\RoguePlanet" ascii //weight: 50
        $x_1_2 = "MpManagerOpen" ascii //weight: 1
        $x_1_3 = "MpScanStart" ascii //weight: 1
        $x_1_4 = "MpThreatEnumerate" ascii //weight: 1
        $x_1_5 = "NtQueryDirectoryObject" ascii //weight: 1
        $x_1_6 = "HarddiskVolumeShadowCopy" ascii //weight: 1
        $x_1_7 = "OpenProcessToken" ascii //weight: 1
        $x_1_8 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_9 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_10 = "DuplicateTokenEx" ascii //weight: 1
        $x_1_11 = "CreateProcessAsUserW" ascii //weight: 1
        $x_1_12 = "SeImpersonatePrivilege" ascii //weight: 1
        $x_1_13 = "OpenVirtualDisk" ascii //weight: 1
        $x_1_14 = "AttachVirtualDisk" ascii //weight: 1
        $x_1_15 = "GetVirtualDiskPhysicalPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RoguePlanet_GVA_2147971362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RoguePlanet.GVA!MTB"
        threat_id = "2147971362"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RoguePlanet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\.\\pipe\\RoguePlanet" wide //weight: 1
        $x_1_2 = "\\wermgr.exe:WDFOO" wide //weight: 1
        $x_1_3 = "\\%TEMP%\\RP_" wide //weight: 1
        $x_1_4 = "HarddiskVolumeShadowCopy" wide //weight: 1
        $x_1_5 = "MpClient.dll" wide //weight: 1
        $x_1_6 = "InstallLocation" wide //weight: 1
        $x_1_7 = "SeImpersonatePrivilege" wide //weight: 1
        $x_1_8 = "\\wdtest_temp" wide //weight: 1
        $x_1_9 = "SOFTWARE\\Microsoft\\Windows Defender" wide //weight: 1
        $x_1_10 = "Successfully accessed volume shadow copy" ascii //weight: 1
        $x_1_11 = "MpScanStart" ascii //weight: 1
        $x_1_12 = "MpScanResult" ascii //weight: 1
        $x_1_13 = "MpThreatOpen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RoguePlanet_DB_2147971401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RoguePlanet.DB!MTB"
        threat_id = "2147971401"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RoguePlanet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "113"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "\\\\.\\pipe\\" ascii //weight: 50
        $x_50_2 = "\\??\\%TEMP%\\" ascii //weight: 50
        $x_1_3 = "MpManagerOpen" ascii //weight: 1
        $x_1_4 = "MpScanStart" ascii //weight: 1
        $x_1_5 = "MpThreatEnumerate" ascii //weight: 1
        $x_1_6 = "NtQueryDirectoryObject" ascii //weight: 1
        $x_1_7 = "OpenProcessToken" ascii //weight: 1
        $x_1_8 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_9 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_10 = "DuplicateTokenEx" ascii //weight: 1
        $x_1_11 = "CreateProcessAsUserW" ascii //weight: 1
        $x_1_12 = "SeImpersonatePrivilege" ascii //weight: 1
        $x_1_13 = "OpenVirtualDisk" ascii //weight: 1
        $x_1_14 = "AttachVirtualDisk" ascii //weight: 1
        $x_1_15 = "GetVirtualDiskPhysicalPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RoguePlanet_DC_2147971402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RoguePlanet.DC!MTB"
        threat_id = "2147971402"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RoguePlanet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "48"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\\\.\\pipe\\" ascii //weight: 10
        $x_10_2 = "\\??\\%TEMP%\\" ascii //weight: 10
        $x_10_3 = "MpClient.dll" ascii //weight: 10
        $x_10_4 = "SOFTWARE\\Microsoft\\Windows Defender" ascii //weight: 10
        $x_1_5 = "MpManagerOpen" ascii //weight: 1
        $x_1_6 = "MpScanStart" ascii //weight: 1
        $x_1_7 = "MpThreatEnumerate" ascii //weight: 1
        $x_1_8 = "HarddiskVolumeShadowCopy" ascii //weight: 1
        $x_1_9 = "OpenProcessToken" ascii //weight: 1
        $x_1_10 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_11 = "SeImpersonatePrivilege" ascii //weight: 1
        $x_1_12 = "VirtualDisk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

