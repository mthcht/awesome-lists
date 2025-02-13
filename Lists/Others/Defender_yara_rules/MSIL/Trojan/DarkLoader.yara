rule Trojan_MSIL_DarkLoader_2147767198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkLoader!MTB"
        threat_id = "2147767198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HttpWebRequest" ascii //weight: 1
        $x_1_2 = "System.Net" ascii //weight: 1
        $x_1_3 = "Stream" ascii //weight: 1
        $x_1_4 = "System.IO" ascii //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = "HttpWebResponse" ascii //weight: 1
        $x_1_7 = "ServicePointManager" ascii //weight: 1
        $x_1_8 = "set_SecurityProtocol" ascii //weight: 1
        $x_1_9 = "SecurityProtocolType" ascii //weight: 1
        $x_1_10 = "WebRequest" ascii //weight: 1
        $x_1_11 = "Create" ascii //weight: 1
        $x_1_12 = "set_Method" ascii //weight: 1
        $x_1_13 = "RegistryKeyPermissionCheck" ascii //weight: 1
        $x_1_14 = "Startup" wide //weight: 1
        $x_1_15 = "Select * from Win32_ComputerSystem" wide //weight: 1
        $x_1_16 = "Model" wide //weight: 1
        $x_1_17 = "VIRTUAL" wide //weight: 1
        $x_1_18 = "VirtualBox" wide //weight: 1
        $x_1_19 = "vmware" wide //weight: 1
        $x_1_20 = "SbieDll.dll" wide //weight: 1
        $x_1_21 = ".vbs" wide //weight: 1
        $x_1_22 = "CreateObject(\"WScript.Shell\").Run \"\"\"" wide //weight: 1
        $x_1_23 = "\"\"\", 0, False" wide //weight: 1
        $x_1_24 = "GetDelegateForFunctionPointer" ascii //weight: 1
        $x_1_25 = "Manufacturer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (22 of ($x*))
}

rule Trojan_MSIL_DarkLoader_2147767198_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkLoader!MTB"
        threat_id = "2147767198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Woops" wide //weight: 1
        $x_1_2 = "GetThreadContext" wide //weight: 1
        $x_1_3 = "Wow64GetThreadContext" wide //weight: 1
        $x_1_4 = "ReadProcessMemory" wide //weight: 1
        $x_1_5 = "ZwUnmapViewOfSection" wide //weight: 1
        $x_1_6 = "WriteProcessMemory" wide //weight: 1
        $x_1_7 = "ThreadContext" wide //weight: 1
        $x_1_8 = "Wow64ThreadContext" wide //weight: 1
        $x_1_9 = "itself" wide //weight: 1
        $x_1_10 = "kernel32" wide //weight: 1
        $x_1_11 = "Wow64SetThreadContext" wide //weight: 1
        $x_1_12 = "SetThreadContext" wide //weight: 1
        $x_1_13 = "VirtualAllocEx" wide //weight: 1
        $x_1_14 = "ntdll" wide //weight: 1
        $x_1_15 = "CreateProcessA" wide //weight: 1
        $x_1_16 = "ResumeThread" wide //weight: 1
        $x_1_17 = "trump2020" wide //weight: 1
        $x_1_18 = "GetManifestResourceStream" wide //weight: 1
        $x_1_19 = "CopyTo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

