rule Trojan_Win32_Cameobe_A_2147639076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cameobe.A"
        threat_id = "2147639076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cameobe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "BecomeAHero_" ascii //weight: 1
        $x_1_2 = "DoAmnBarrellRoll_" wide //weight: 1
        $x_1_3 = ".\\pipe\\DoItFaggot" wide //weight: 1
        $x_1_4 = {2f 77 65 62 68 70 3f [0-5] 26 71 3d [0-5] 6f 75 74 70 75 74 3d 6a 73}  //weight: 1, accuracy: Low
        $x_1_5 = {47 45 54 20 2f 6d 6f 6e 2f 3f 64 3d 63 69 64 3d [0-16] 26 61 69 64 3d [0-32] 26 63 6f 64 65 3d}  //weight: 1, accuracy: Low
        $x_1_6 = "\", StartProt" ascii //weight: 1
        $x_1_7 = {2f 75 31 2f 3f 64 3d 63 69 64 3d [0-16] 26 61 69 64 3d [0-32] 26 73 75 62 3d}  //weight: 1, accuracy: Low
        $x_1_8 = {26 70 61 72 3d [0-5] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-5] 5f 54 44 00 2f 65}  //weight: 1, accuracy: Low
        $x_3_9 = {66 3d 05 00 76 0b 66 05 fb ff 66 89 44 24 1e eb 4d 66 8b 4c 24 1a 66 05 19 00 66 83 f9 02 66 89 44 24 1e 75 19}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

