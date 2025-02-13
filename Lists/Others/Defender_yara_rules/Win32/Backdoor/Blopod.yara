rule Backdoor_Win32_Blopod_A_2147725376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blopod.A!bit"
        threat_id = "2147725376"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blopod"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {26 67 72 6f 75 70 3d 00 72 65 73 6f 75 72 63 65 2e 70 68 70 3f 68 77 69 64 3d}  //weight: 3, accuracy: High
        $x_1_2 = "HTTP-flood" ascii //weight: 1
        $x_1_3 = "TCP-flood" ascii //weight: 1
        $x_1_4 = "Download and execute" ascii //weight: 1
        $x_1_5 = "schtasks /create /tn " ascii //weight: 1
        $x_1_6 = {5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c [0-32] 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_7 = {61 74 74 72 69 62 20 2b 73 20 2b 68 20 [0-32] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_8 = "taskkill /f /im " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

