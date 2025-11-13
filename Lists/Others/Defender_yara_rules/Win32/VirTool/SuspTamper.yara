rule VirTool_Win32_SuspTamper_A_2147957415_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspTamper.A"
        threat_id = "2147957415"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 4e 00 53 00 75 00 64 00 6f 00 [0-4] 2e 00 65 00 78 00 65 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = " -ShowWindowMode:Hide " wide //weight: 10
        $x_2_3 = "Add-MpPreference -Exclusion" wide //weight: 2
        $x_2_4 = {53 00 65 00 63 00 48 00 65 00 61 00 6c 00 74 00 68 00 55 00 49 00 [0-8] 20 00 7c 00 20 00 52 00 65 00 6d 00 6f 00 76 00 65 00 2d 00 41 00 70 00 70 00 78 00 50 00 61 00 63 00 6b 00 61 00 67 00 65 00}  //weight: 2, accuracy: Low
        $x_2_5 = {41 00 70 00 70 00 72 00 65 00 70 00 2e 00 43 00 68 00 78 00 41 00 70 00 70 00 [0-8] 20 00 7c 00 20 00 52 00 65 00 6d 00 6f 00 76 00 65 00 2d 00 41 00 70 00 70 00 78 00 50 00 61 00 63 00 6b 00 61 00 67 00 65 00}  //weight: 2, accuracy: Low
        $x_2_6 = "reg delete " wide //weight: 2
        $x_2_7 = "taskkill /f /im " wide //weight: 2
        $x_1_8 = {63 00 6d 00 64 00 [0-8] 20 00 2f 00 63 00 20 00}  //weight: 1, accuracy: Low
        $x_1_9 = "PowerShell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

