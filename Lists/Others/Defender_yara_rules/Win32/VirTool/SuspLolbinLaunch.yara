rule VirTool_Win32_SuspLolbinLaunch_G_2147982235_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspLolbinLaunch.G"
        threat_id = "2147982235"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 00 00 22 10 10 05 63 75 72 6c 22}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00 22 18 18 07 6d 73 69 65 78 63 22}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 69 00 70 00 79 00 77 00 2e 00 65 00 78 00 65 00 00 00 22 10 10 05 69 70 79 77 22}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 69 00 70 00 79 00 77 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00 22 10 10 07 69 70 79 77 33 32 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

