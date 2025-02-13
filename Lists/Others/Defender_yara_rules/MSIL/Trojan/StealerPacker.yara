rule Trojan_MSIL_StealerPacker_2147771496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerPacker!MTB"
        threat_id = "2147771496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_2 = "OutputDebugString" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_5 = "NtQueryInformationProcess" ascii //weight: 1
        $x_1_6 = "UrlDecode" ascii //weight: 1
        $x_1_7 = "get_qqqqqqqqqqqqqqqqqqqqqqqqqqqqq" ascii //weight: 1
        $x_1_8 = "AppDomain" ascii //weight: 1
        $x_1_9 = "get_CurrentDomain" ascii //weight: 1
        $x_1_10 = "FromBase64CharArray" ascii //weight: 1
        $x_1_11 = "Application" ascii //weight: 1
        $x_1_12 = "EnableVisualStyles" ascii //weight: 1
        $x_1_13 = "SetCompatibleTextRenderingDefault" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StealerPacker_2147771496_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StealerPacker!MTB"
        threat_id = "2147771496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StealerPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dy*|/nam*|/icDl*|/lInvo*|/ke" wide //weight: 1
        $x_1_2 = "RegAsm.exe" wide //weight: 1
        $x_1_3 = "#cmd" wide //weight: 1
        $x_1_4 = "kernel32.dll" wide //weight: 1
        $x_1_5 = "Wow64GetThreadContext" wide //weight: 1
        $x_1_6 = "GetThreadContext" wide //weight: 1
        $x_1_7 = "ReadProcessMemory" wide //weight: 1
        $x_1_8 = "VirtualAllocEx" wide //weight: 1
        $x_1_9 = "WriteProcessMemory" wide //weight: 1
        $x_1_10 = "Wow64SetThreadContext" wide //weight: 1
        $x_1_11 = "SetThreadContext" wide //weight: 1
        $x_1_12 = "ResumeThread" wide //weight: 1
        $x_1_13 = "CreateProcessAsUser" wide //weight: 1
        $x_1_14 = "Framework64" wide //weight: 1
        $x_1_15 = "MethodImplAttributes" wide //weight: 1
        $x_1_16 = "PreserveSig" wide //weight: 1
        $x_1_17 = "A*|/sse*|/mblyBui*|/lderAc*|/cess" wide //weight: 1
        $x_1_18 = "System.Runtime.InteropServices" wide //weight: 1
        $x_1_19 = "CallingConvention" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

