rule HackTool_Win32_DevilsTongueDriver_B_2147785103_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DevilsTongueDriver.B!dha"
        threat_id = "2147785103"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DevilsTongueDriver"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {64 3a 5c 70 72 6f 6a 65 6b 74 65 5c 64 65 76 69 63 65 64 72 69 76 65 72 5c 70 68 79 73 69 63 61 6c 6d 65 6d 6f 72 79 76 69 65 77 65 72 5c 77 66 6f 72 6d 73 5c 76 31 2e 30 2e 30 2e 30 5c 64 72 69 76 65 72 5c 6f 62 6a 66 72 65 5f 77 69 6e 37 5f [0-5] 5c [0-5] 5c 70 68 79 73 6d 65 6d 2e 70 64 62}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

