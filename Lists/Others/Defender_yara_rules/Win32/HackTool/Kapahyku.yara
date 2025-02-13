rule HackTool_Win32_Kapahyku_A_2147707350_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Kapahyku.A"
        threat_id = "2147707350"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Kapahyku"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\KRT settings\\Reset" ascii //weight: 1
        $x_1_2 = "KASPERSKY RESET TRIAL" ascii //weight: 1
        $x_1_3 = "forum.ru-board" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

