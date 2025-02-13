rule Backdoor_Win32_Saluchtra_A_2147688793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Saluchtra.A!dha"
        threat_id = "2147688793"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Saluchtra"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Users\\Tranchulas\\" ascii //weight: 1
        $x_1_2 = {2f 66 65 74 63 68 5f 75 70 64 61 74 65 73 5f [0-8] 2e 70 68 70 3f 63 6f 6d 70 6e 61 6d 65 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {45 78 70 65 63 74 3a 00 43 4f 4d 50 55 54 45 52 4e 41 4d 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Saluchtra_B_2147688794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Saluchtra.B!dha"
        threat_id = "2147688794"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Saluchtra"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".php?compname=" ascii //weight: 1
        $x_1_2 = "/c wmic diskdrive list brief > " ascii //weight: 1
        $x_1_3 = "\\percf001.dat" ascii //weight: 1
        $x_1_4 = {56 42 4f 58 00 00 00 00 56 4d 77 61 72 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

