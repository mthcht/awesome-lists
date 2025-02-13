rule Trojan_Win32_Timpin_2147616243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Timpin"
        threat_id = "2147616243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Timpin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_2 = {74 6d 70 24 24 24 [0-46] 69 6e 69}  //weight: 10, accuracy: Low
        $x_1_3 = {00 66 69 6c 65 75 72 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 64 6f 77 6e 6c 6f 61 64 66 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {2e 63 6f 2e 6b 72 2f 75 70 ?? ?? ?? ?? 2e 70 68 70 00}  //weight: 1, accuracy: Low
        $x_1_6 = {00 66 69 6c 65 63 6f 75 6e 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 66 69 6c 65 6e 61 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

