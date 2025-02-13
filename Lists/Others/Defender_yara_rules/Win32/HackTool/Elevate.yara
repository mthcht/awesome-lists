rule HackTool_Win32_Elevate_B_2147718781_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Elevate.B"
        threat_id = "2147718781"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Elevate"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\pipe\\TIOR_In" wide //weight: 1
        $x_1_2 = "\\\\.\\pipe\\TIOR_Out" wide //weight: 1
        $x_1_3 = "\\\\.\\pipe\\TIOR_Err" wide //weight: 1
        $x_1_4 = "TIOR: [in]" wide //weight: 1
        $x_1_5 = "TIOR: [out]" wide //weight: 1
        $x_1_6 = "TIOR: [err]" wide //weight: 1
        $x_1_7 = "w7e_TIORShell" wide //weight: 1
        $x_1_8 = "w7e_TIORArgs" wide //weight: 1
        $x_1_9 = "w7e_TIORDir" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

