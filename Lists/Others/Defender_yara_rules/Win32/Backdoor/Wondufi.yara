rule Backdoor_Win32_Wondufi_A_2147710660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wondufi.A"
        threat_id = "2147710660"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wondufi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {3f 25 73 3d [0-5] 67 65 74 6e 61 6d 65 69 6e 66 6f}  //weight: 4, accuracy: Low
        $x_4_2 = "GetCurrentJPGImageState" wide //weight: 4
        $x_4_3 = "/api.php;" wide //weight: 4
        $x_4_4 = "*.0pxm" wide //weight: 4
        $x_4_5 = "#opex#" wide //weight: 4
        $x_4_6 = {68 00 77 00 3a 00 00 00 7c 00 62 00 69 00 3a 00}  //weight: 4, accuracy: High
        $x_1_7 = "|la:" wide //weight: 1
        $x_1_8 = "|oa:" wide //weight: 1
        $x_1_9 = "|bv:" wide //weight: 1
        $x_1_10 = "|vr:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_4_*) and 1 of ($x_1_*))) or
            ((6 of ($x_4_*))) or
            (all of ($x*))
        )
}

