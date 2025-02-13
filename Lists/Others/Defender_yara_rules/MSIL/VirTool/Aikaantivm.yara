rule VirTool_MSIL_Aikaantivm_GG_2147769553_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Aikaantivm.GG!MTB"
        threat_id = "2147769553"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Aikaantivm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "73"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_2 = "Select * from Win32_ComputerSystem" ascii //weight: 10
        $x_10_3 = "microsoft corporation" ascii //weight: 10
        $x_10_4 = "VIRTUAL" ascii //weight: 10
        $x_10_5 = "vmware" ascii //weight: 10
        $x_10_6 = "VirtualBox" ascii //weight: 10
        $x_10_7 = "SbieDll.dll" ascii //weight: 10
        $x_1_8 = "cmdvrt32.dll" ascii //weight: 1
        $x_1_9 = "SxIn.dll" ascii //weight: 1
        $x_1_10 = "WriteProcessMemory" ascii //weight: 1
        $x_1_11 = "NtUnmapViewOfSection" ascii //weight: 1
        $x_1_12 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Aikaantivm_GG_2147769553_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Aikaantivm.GG!MTB"
        threat_id = "2147769553"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Aikaantivm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "64"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_2 = "Select * from Win32_ComputerSystem" ascii //weight: 10
        $x_10_3 = "microsoft corporation" ascii //weight: 10
        $x_10_4 = "VIRTUAL" ascii //weight: 10
        $x_10_5 = "vmware" ascii //weight: 10
        $x_10_6 = "VirtualBox" ascii //weight: 10
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_8 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_9 = "CreateFileMapping" ascii //weight: 1
        $x_1_10 = "UnmapViewOfFile" ascii //weight: 1
        $x_1_11 = "MapViewOfFile" ascii //weight: 1
        $x_1_12 = "NtQueryInformationProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

