rule HackTool_Win32_SAMInside_A_2147725306_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SAMInside.A"
        threat_id = "2147725306"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SAMInside"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SAM\\Domains\\Account\\Users\\Names registry hive reading error!" ascii //weight: 1
        $x_1_2 = "SAM\\Domains\\Account registry hive reading error!" ascii //weight: 1
        $x_1_3 = "InsidePro, http://www.InsidePro.com" ascii //weight: 1
        $x_1_4 = "GetHashes <SAM registry file> [System key file]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

