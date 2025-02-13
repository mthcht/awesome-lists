rule HackTool_Win32_KMSActivator_A_2147743253_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/KMSActivator.A!MSR"
        threat_id = "2147743253"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "KMSActivator"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KMS-QADhook.dll" wide //weight: 1
        $x_1_2 = "SppExtComObj.exe" wide //weight: 1
        $x_1_3 = "SppExtComObjHook.dll" wide //weight: 1
        $x_1_4 = "sppsvc.exe" wide //weight: 1
        $x_1_5 = "writeprocessmemory" ascii //weight: 1
        $x_1_6 = "SuspendThread" ascii //weight: 1
        $x_1_7 = "ResumeThread" ascii //weight: 1
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_9 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule HackTool_Win32_KMSActivator_G_2147766464_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/KMSActivator.G!MSR"
        threat_id = "2147766464"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "KMSActivator"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KMS-R@1nHook.pdb" ascii //weight: 1
        $x_1_2 = "KMS-R@1nHook.dll" ascii //weight: 1
        $x_1_3 = "get_KMS_R_1nHook32EXE" ascii //weight: 1
        $x_1_4 = "Activator.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

