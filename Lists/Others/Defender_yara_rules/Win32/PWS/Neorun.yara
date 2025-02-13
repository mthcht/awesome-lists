rule PWS_Win32_Neorun_A_2147657564_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Neorun.A"
        threat_id = "2147657564"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Neorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 75 6e 50 72 6f 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "%s\\%c%c%c%c%c%c.TMP" wide //weight: 1
        $x_1_3 = "\\ieonline.ini" wide //weight: 1
        $x_1_4 = "\\msadp32.acm" wide //weight: 1
        $x_1_5 = {ac 33 06 03 89 45 ?? c7 45 ?? 16 65 fa 10 89 45 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_Neorun_B_2147657565_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Neorun.B"
        threat_id = "2147657565"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Neorun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MyRealWork" ascii //weight: 1
        $x_1_2 = "RunProcess" ascii //weight: 1
        $x_1_3 = "WinSta0\\Default" ascii //weight: 1
        $x_1_4 = "WorkRunThread" ascii //weight: 1
        $x_1_5 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" ascii //weight: 1
        $x_1_6 = "Neo,welcome to the desert of real." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

