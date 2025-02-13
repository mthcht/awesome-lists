rule Worm_Win32_Mocon_A_2147624659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mocon.A"
        threat_id = "2147624659"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mocon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "[AutoRun]" ascii //weight: 10
        $x_10_2 = "\\autorun.inf" ascii //weight: 10
        $x_10_3 = {6f 70 65 6e 3d [0-16] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_4 = {3c 66 6f 72 6d 20 6e 61 6d 65 3d 6b 20 6d 65 74 68 6f 64 3d 70 6f 73 74 20 61 63 74 69 6f 6e 3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e [0-32] 2e 75 65 75 6f 2e 63 6f 6d 2f [0-16] 2e 70 68 70 22 3e 3c 69 6e 70 75 74 20 74 79 70 65 3d 68 69 64 64 65 6e 20 6e 61 6d 65 3d 64 65 20 76 61 6c 75 65 3d 22 22 3e 3c 74 65 78 74 61 72 65 61 20 6e 61 6d 65 3d 74 65 78 74 6f 3e}  //weight: 10, accuracy: Low
        $x_1_5 = "/cssrs.exe" ascii //weight: 1
        $x_1_6 = "attrib +h +s +r" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

