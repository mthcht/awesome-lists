rule VirTool_Win32_CryptDropper_2147775375_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CryptDropper!MTB"
        threat_id = "2147775375"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptDropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bsearch" ascii //weight: 1
        $x_1_2 = "qsort" ascii //weight: 1
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualFree" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "VirtualQuery" ascii //weight: 1
        $x_1_7 = "okernel32.dll" wide //weight: 1
        $x_1_8 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_9 = "GetCurrentProcess" ascii //weight: 1
        $x_1_10 = "TerminateProcess" ascii //weight: 1
        $x_1_11 = "SetFilePointerEx" ascii //weight: 1
        $x_1_12 = "DecodePointer" ascii //weight: 1
        $x_1_13 = "Qkkbal" ascii //weight: 1
        $x_1_14 = "SHELLCODEEXECUTE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

