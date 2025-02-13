rule Worm_Win32_Hiprast_A_2147652852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hiprast.A"
        threat_id = "2147652852"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hiprast"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ParsiBash" ascii //weight: 1
        $x_1_2 = "HMDCorP.vbp" wide //weight: 1
        $x_1_3 = "Timer_CopyAhang" ascii //weight: 1
        $x_1_4 = "HMD Group" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

