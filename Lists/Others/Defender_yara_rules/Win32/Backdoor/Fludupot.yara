rule Backdoor_Win32_Fludupot_A_2147631488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fludupot.A"
        threat_id = "2147631488"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fludupot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a f5 04 00 00 00 c2 f5 00 00 00 00 c7 1c}  //weight: 1, accuracy: High
        $x_1_2 = {53 65 6e 64 46 6c 6f 6f 64 [0-4] 53 74 6f 70 46 6c 6f 6f 64 [0-4] 53 74 61 72 74 54 43 50 [0-4] 53 74 6f 70 54 43 50 [0-4] 53 74 61 72 74 44 6f 53 [0-4] 53 74 6f 70 44 6f 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

