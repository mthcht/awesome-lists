rule Trojan_Win32_Suspfsiutil_A_2147819906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspfsiutil.A!ibt"
        threat_id = "2147819906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspfsiutil"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 00 73 00 75 00 74 00 69 00 6c 00 [0-16] 73 00 65 00 74 00 7a 00 65 00 72 00 6f 00 64 00 61 00 74 00 61 00}  //weight: 2, accuracy: Low
        $x_2_2 = {6f 00 66 00 66 00 73 00 65 00 74 00 3d 00 30 00 [0-5] 6c 00 65 00 6e 00 67 00 74 00 68 00 3d 00 35 00 32 00 34 00 32 00 38 00 38 00}  //weight: 2, accuracy: Low
        $x_2_3 = "del /f /q" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

