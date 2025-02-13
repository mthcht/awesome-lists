rule Backdoor_Win32_Antilam_U_2147640746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Antilam.U"
        threat_id = "2147640746"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Antilam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TFRMFILEMANAGER" wide //weight: 2
        $x_2_2 = "SpdRemoveWallPaperClick" ascii //weight: 2
        $x_3_3 = "SpdActCrazyClick" ascii //weight: 3
        $x_3_4 = "TFRMEXTRAFUN" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

