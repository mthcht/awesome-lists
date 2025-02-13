rule Backdoor_Win32_Sivuxa_B_2147602910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Sivuxa.B"
        threat_id = "2147602910"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Sivuxa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 6f 6f 6b 49 6e 69 74 00 00 00 00 48 6f 6f 6b 44 6f 6e 65}  //weight: 1, accuracy: High
        $x_1_2 = "{64D45A93-00DD-41cb-A187-FF02A15AE32B}" ascii //weight: 1
        $x_1_3 = "if exist \".\\%s\" goto :loop" ascii //weight: 1
        $x_1_4 = {5c 5c 2e 5c 53 49 43 45 00 00 00 00 5c 5c 2e 5c 4e 54 49 43 45 00 00 00 64 6c 69 6e 73 74 68 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

