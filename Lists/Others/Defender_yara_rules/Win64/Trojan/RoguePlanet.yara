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

