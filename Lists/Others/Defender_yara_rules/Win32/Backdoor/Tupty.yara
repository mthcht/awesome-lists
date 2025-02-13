rule Backdoor_Win32_Tupty_A_2147651598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Tupty.A"
        threat_id = "2147651598"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Tupty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WelCome To Tport" ascii //weight: 1
        $x_1_2 = "Execute The Command with Longon User Failed" ascii //weight: 1
        $x_1_3 = {49 6e 73 74 61 6c 6c 54 65 72 6d 20 50 6f 72 74 20 [0-32] 2d 2d 3e 49 6e 73 74 61 6c 6c 20 4e 65 77 20 54 65 72 6d 69 6e 61 6c 20 50 6f 72 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

