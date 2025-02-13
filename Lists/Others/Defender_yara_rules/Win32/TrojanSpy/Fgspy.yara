rule TrojanSpy_Win32_Fgspy_A_2147595005_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Fgspy.A"
        threat_id = "2147595005"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Fgspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Ring0Port.sys" ascii //weight: 10
        $x_10_2 = "Hidden_Proc_Dll.dll" ascii //weight: 10
        $x_10_3 = "KTHide" ascii //weight: 10
        $x_1_4 = "registry\\machine\\system\\CurrentControlSet\\Services\\KernelPort" wide //weight: 1
        $x_1_5 = "Process32Next" ascii //weight: 1
        $x_1_6 = "Process32First" ascii //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_8 = "ZwQuerySystemInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

