rule HackTool_Win32_SuspAdcsTool_A_2147787735_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SuspAdcsTool.A"
        threat_id = "2147787735"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspAdcsTool"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "find /vulnerable" ascii //weight: 1
        $x_1_2 = "Vulnerable Certificates Templates" ascii //weight: 1
        $x_1_3 = "/enrollcert:C:\\Temp\\enroll.pfx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

