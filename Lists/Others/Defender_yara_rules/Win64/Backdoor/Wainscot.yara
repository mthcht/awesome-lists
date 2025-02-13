rule Backdoor_Win64_Wainscot_A_2147902510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Wainscot.A!dha"
        threat_id = "2147902510"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Wainscot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3f 75 70 6c 6f 0f 85 e9 03 00 00 66 81 7f ?? 61 64 66 90 0f 85 db 03 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 fe 09 0f 85 4d 01 00 00 49 ba 73 68 65 6c 6c 65 78 65 4c 39 17 0f 85 44 01 00 00 80 7f ?? 63 0f 85 3a 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

