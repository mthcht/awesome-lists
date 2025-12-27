rule VirTool_Win32_SuspScheduledTaskInstallation_D_2147958112_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspScheduledTaskInstallation.D"
        threat_id = "2147958112"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspScheduledTaskInstallation"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "schtasks" wide //weight: 1
        $x_1_2 = " /create /ru system /sc daily /tr " wide //weight: 1
        $x_1_3 = "cmd /c powershell" wide //weight: 1
        $x_1_4 = {20 00 2d 00 65 00 70 00 20 00 62 00 79 00 70 00 61 00 73 00 73 00 20 00 2d 00 66 00 69 00 6c 00 65 00 20 00 [0-255] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-128] 20 00 2f 00 74 00 6e 00 20 00 77 00 69 00 6e 00 33 00 32 00 74 00 69 00 6d 00 65 00 73 00 20 00 2f 00 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

