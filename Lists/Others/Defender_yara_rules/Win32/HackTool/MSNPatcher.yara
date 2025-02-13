rule HackTool_Win32_MSNPatcher_A_2147630093_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/MSNPatcher.gen!A"
        threat_id = "2147630093"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MSNPatcher"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {3b 7a 14 72 1f 8b 42 14 03 42 10 3b f8 73 15 8b 42 14 2b f8 8b 42 0c 03 c7 8b c8 33 c0 40 5e 5f c9 c2 08 00}  //weight: 100, accuracy: High
        $x_10_2 = {06 b6 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 4d 53 4e 4d 65 73 73 65 6e 67 65 72}  //weight: 10, accuracy: High
        $x_10_3 = "MSN\\Windows Messenger Universal Loader" ascii //weight: 10
        $x_1_4 = "jnrz.2kzone.net" ascii //weight: 1
        $x_1_5 = "Universal JnrzLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

