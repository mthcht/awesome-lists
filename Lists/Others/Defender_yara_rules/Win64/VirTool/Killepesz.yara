rule VirTool_Win64_Killepesz_A_2147912789_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Killepesz.A!MTB"
        threat_id = "2147912789"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Killepesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Removed PPL" ascii //weight: 1
        $x_1_2 = "IOCTL_PPLK_UNPROTECT" ascii //weight: 1
        $x_1_3 = {64 69 73 61 62 6c 65 [0-32] 6d 69 74 69 67 61 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = "Driver unloaded" ascii //weight: 1
        $x_1_5 = "rootkit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

