rule DoS_Win32_MadPebble_B_2147962591_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/MadPebble.B!dha"
        threat_id = "2147962591"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "MadPebble"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 00 73 00 c7 [0-6] 75 00 74 00 c7 [0-5] 69 00 6c 00 c7 [0-5] 2e 00 65 00 c7 [0-5] 78 00 65 00 c7 [0-5] 20 00 66 00}  //weight: 1, accuracy: Low
        $x_1_2 = {73 00 65 00 c7 [0-5] 74 00 7a 00 c7 [0-5] 65 00 72 00 c7 [0-5] 6f 00 64 00 c7 [0-5] 61 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

