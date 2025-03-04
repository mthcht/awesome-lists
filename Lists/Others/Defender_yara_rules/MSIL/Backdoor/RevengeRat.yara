rule Backdoor_MSIL_RevengeRAT_AD_2147796837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/RevengeRAT.AD!MTB"
        threat_id = "2147796837"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevengeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lime" ascii //weight: 1
        $x_1_2 = "EXECUTION_STATE" ascii //weight: 1
        $x_1_3 = "TcpReceive" ascii //weight: 1
        $x_1_4 = "TcpSend" ascii //weight: 1
        $x_1_5 = "GetHardDiskSerialNumber" ascii //weight: 1
        $x_1_6 = "GetAV" ascii //weight: 1
        $x_1_7 = "ES_CONTINUOUS" ascii //weight: 1
        $x_1_8 = "ES_DISPLAY_REQUIRED" ascii //weight: 1
        $x_1_9 = "ES_SYSTEM_REQUIRED" ascii //weight: 1
        $x_1_10 = "currentMutex" ascii //weight: 1
        $x_1_11 = "ParameterizedThreadStart" ascii //weight: 1
        $x_1_12 = "WaitForPendingFinalizers" ascii //weight: 1
        $x_1_13 = "get_MachineName" ascii //weight: 1
        $x_1_14 = "get_UserName" ascii //weight: 1
        $x_1_15 = "get_OSFullName" ascii //weight: 1
        $x_1_16 = "get_TotalPhysicalMemory" ascii //weight: 1
        $x_1_17 = "GetHostName" ascii //weight: 1
        $x_1_18 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_19 = "SELECT * FROM FirewallProduct" wide //weight: 1
        $x_1_20 = "SystemDrive" wide //weight: 1
        $x_1_21 = "select * from Win32_Processor" wide //weight: 1
        $x_1_22 = "root\\SecurityCenter" wide //weight: 1
        $x_1_23 = "HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR\\0" wide //weight: 1
        $x_1_24 = "ProcessorNameString" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

