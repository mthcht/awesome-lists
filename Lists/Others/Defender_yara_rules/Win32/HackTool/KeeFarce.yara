rule HackTool_Win32_KeeFarce_2147707417_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/KeeFarce"
        threat_id = "2147707417"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "KeeFarce"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeeFarceDLL.dll" wide //weight: 1
        $x_1_2 = "[.] Injecting BootstrapDLL into %d" ascii //weight: 1
        $x_1_3 = "keepass_export.csv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

