rule DDoS_Win32_Resod_A_2147609698_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Resod.A"
        threat_id = "2147609698"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Resod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6f 63 65 73 73 00 00 4b 45 52 4e 45 4c 33 32 00 00 00 00 44 44 6f 53 65 72 00 00 5c 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

