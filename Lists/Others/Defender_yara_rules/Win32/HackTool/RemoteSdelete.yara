rule HackTool_Win32_RemoteSdelete_A_2147816570_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/RemoteSdelete.A"
        threat_id = "2147816570"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RemoteSdelete"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "C:\\Windows\\System32\\cmd.exe C:\\" wide //weight: 10
        $x_1_2 = " /C " wide //weight: 1
        $x_1_3 = {2e 00 65 00 78 00 65 00 [0-10] 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-5] 2d 00 72 00 [0-10] 2d 00 71 00 [0-16] 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 00 65 00 78 00 65 00 [0-10] 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-5] 2d 00 71 00 [0-10] 2d 00 72 00 [0-16] 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 00 65 00 78 00 65 00 [0-10] 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-5] 2d 00 72 00 [0-10] 2d 00 71 00 [0-16] 63 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 00 65 00 78 00 65 00 [0-10] 2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 [0-5] 2d 00 71 00 [0-10] 2d 00 72 00 [0-16] 63 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

