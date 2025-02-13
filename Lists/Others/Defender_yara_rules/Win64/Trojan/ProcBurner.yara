rule Trojan_Win64_ProcBurner_RPW_2147835183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ProcBurner.RPW!MTB"
        threat_id = "2147835183"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ProcBurner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\\\.\\Rtcore64" wide //weight: 10
        $x_1_2 = "CreateFileW" ascii //weight: 1
        $x_1_3 = "GetLogicalDriveStringsW" ascii //weight: 1
        $x_1_4 = "RtlGetNtVersionNumbers" ascii //weight: 1
        $x_1_5 = "RtlAdjustPrivilege" ascii //weight: 1
        $x_1_6 = "GetCurrentProcessId" ascii //weight: 1
        $x_1_7 = "OpenProcess" ascii //weight: 1
        $x_1_8 = "LocalAlloc" ascii //weight: 1
        $x_1_9 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_10 = "DeviceIoControl" ascii //weight: 1
        $x_1_11 = "GetFileVersionInfoW" wide //weight: 1
        $x_1_12 = "VerQueryValueW" wide //weight: 1
        $x_1_13 = "find current process objecttable addres" wide //weight: 1
        $x_1_14 = "find current process eprocess address" wide //weight: 1
        $x_1_15 = "level 2 handle table not support" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

