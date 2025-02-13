rule HackTool_Win32_Wincred_H_2147686014_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Wincred.H"
        threat_id = "2147686014"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Wincred"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 43 45 53 45 52 56 49 43 45 00}  //weight: 1, accuracy: High
        $x_1_2 = "(Windows Credentials Editor)" ascii //weight: 1
        $x_1_3 = "Using WCE Windows Service..." ascii //weight: 1
        $x_1_4 = "something terrible happened!" ascii //weight: 1
        $x_1_5 = "Cannot get LSASS.EXE PID!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule HackTool_Win32_Wincred_H_2147740677_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Wincred.H!!Wincred.gen!A"
        threat_id = "2147740677"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Wincred"
        severity = "High"
        info = "Wincred: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 43 45 53 45 52 56 49 43 45 00}  //weight: 1, accuracy: High
        $x_1_2 = "(Windows Credentials Editor)" ascii //weight: 1
        $x_1_3 = "Using WCE Windows Service..." ascii //weight: 1
        $x_1_4 = "something terrible happened!" ascii //weight: 1
        $x_1_5 = "Cannot get LSASS.EXE PID!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

