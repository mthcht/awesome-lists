rule SoftwareBundler_Win32_Lollipos_198718_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Lollipos"
        threat_id = "198718"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Lollipos"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 72 00 6d 00 5f 00 4c 00 6f 00 6c 00 6c 00 69 00 70 00 6f 00 70 00 01 00 00 01 00 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = "uFrmTB_Lollipop" ascii //weight: 2
        $x_1_3 = "lollipop-network.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

