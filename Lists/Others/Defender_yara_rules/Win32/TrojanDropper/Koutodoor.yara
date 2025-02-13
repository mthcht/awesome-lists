rule TrojanDropper_Win32_Koutodoor_B_2147625900_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Koutodoor.B"
        threat_id = "2147625900"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\\\.\\Global\\rkdoor" ascii //weight: 10
        $x_10_2 = "%s\\%s %s\\%s.dll,%s" ascii //weight: 10
        $x_5_3 = {53 74 61 72 74 20 50 61 67 65 [0-4] 77 77 77 2e 62 61 69 64 75 2e 63 6f 6d [0-4] 3f 74 6e 3d}  //weight: 5, accuracy: Low
        $x_1_4 = "system32\\drivers\\%s.sys" ascii //weight: 1
        $x_1_5 = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

