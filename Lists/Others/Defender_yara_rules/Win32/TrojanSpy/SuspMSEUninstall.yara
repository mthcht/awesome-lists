rule TrojanSpy_Win32_SuspMSEUninstall_A_2147821157_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/SuspMSEUninstall.A"
        threat_id = "2147821157"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMSEUninstall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "2AA3C13E-0531-41B8-AE48-AE28C940A809" wide //weight: 20
        $x_1_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-240] 2d 00 78 00 20 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-240] 2f 00 78 00 20 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-240] 2d 00 75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00}  //weight: 1, accuracy: Low
        $x_1_5 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-240] 2f 00 75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

