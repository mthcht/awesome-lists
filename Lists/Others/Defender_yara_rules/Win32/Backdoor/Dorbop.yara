rule Backdoor_Win32_Dorbop_B_2147720570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dorbop.B!bit"
        threat_id = "2147720570"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorbop"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 68 30 73 74 [0-63] 53 65 72 76 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "c:\\Windows\\%s.exe" ascii //weight: 1
        $x_1_3 = {64 6f 6f 72 6e 61 6d 65 3d 22 63 68 61 72 20 [0-31] 5b 5d 20 3d 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

