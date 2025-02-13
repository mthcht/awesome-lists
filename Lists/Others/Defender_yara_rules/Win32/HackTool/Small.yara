rule HackTool_Win32_Small_B_2147626045_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Small.B"
        threat_id = "2147626045"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{2C2E0EDA-8ACE-4562-9DEC-CC632D946AE6}" ascii //weight: 1
        $x_1_2 = "{ED8D054B-90B8-4B1A-B4E7-BCA20E520993}" ascii //weight: 1
        $x_1_3 = {84 b2 96 b1 b4 ba 1a 10 b6 9c 00 aa 00 34 1d 07}  //weight: 1, accuracy: High
        $x_1_4 = "http://www.158166.com/ShowDj.asp?id=" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Small_C_2147642571_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Small.C"
        threat_id = "2147642571"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AddUserToGroup" ascii //weight: 1
        $x_1_2 = "B.E.N_Duck" ascii //weight: 1
        $x_1_3 = "sethc.exe" wide //weight: 1
        $x_1_4 = "Administrators" wide //weight: 1
        $x_1_5 = "taskmgr.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

