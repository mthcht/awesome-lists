rule Backdoor_Win32_Loony_2147597686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Loony"
        threat_id = "2147597686"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Loony"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s clones to %s on port %s" ascii //weight: 1
        $x_2_2 = {6e 74 56 65 72 73 69 6f 6e 5c 00 79 61 68 6f 6f 20 4d 65 73 73 65 6e}  //weight: 2, accuracy: High
        $x_2_3 = {6b 69 6c 6c 74 68 72 65 61 64 00 70 61 73 73 77 6f 72 64 73 00 6b 65 79 73 00}  //weight: 2, accuracy: High
        $x_2_4 = {73 79 6e 00 73 6f 63 6b 73 34 00 6c 6f 61}  //weight: 2, accuracy: High
        $x_2_5 = {6e 77 6e 63 64 6b 65 79 2e 69 6e 69 00 25 73 5c 25 73}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

