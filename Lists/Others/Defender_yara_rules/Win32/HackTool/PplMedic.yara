rule HackTool_Win32_PplMedic_A_2147845790_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PplMedic.A"
        threat_id = "2147845790"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PplMedic"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {79 d2 c1 b4 6e 96 e9 44 a9 c5 cc af 4a 77 02 3d}  //weight: 1, accuracy: High
        $x_10_2 = {c7 44 24 34 bb 1a b3 4e c7 44 24 ?? b4 f0 eb 43 44 8d 42 04 c7 44 24 ?? 1c b1 cb 32}  //weight: 10, accuracy: Low
        $x_1_3 = "WaaSMedicSvc" ascii //weight: 1
        $x_1_4 = "LaunchDetectionOnly" ascii //weight: 1
        $x_1_5 = "%ws\\UUS\\amd64\\%ws" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Classes\\TypeLib\\%ws\\1.0\\0\\Win64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_PplMedic_B_2147846819_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PplMedic.B"
        threat_id = "2147846819"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PplMedic"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {79 d2 c1 b4 6e 96 e9 44 a9 c5 cc af 4a 77 02 3d}  //weight: 1, accuracy: High
        $x_10_2 = {c7 44 24 34 bb 1a b3 4e c7 44 24 ?? b4 f0 eb 43 44 8d 42 04 c7 44 24 ?? 1c b1 cb 32}  //weight: 10, accuracy: Low
        $x_1_3 = "\\CatRoot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}" ascii //weight: 1
        $x_1_4 = "LaunchDetectionOnly" ascii //weight: 1
        $x_1_5 = "WaaSMedicLogonSessionPipe" ascii //weight: 1
        $x_1_6 = "$CI.CATALOGHINT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

