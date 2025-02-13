rule Backdoor_Win32_Draobo_A_2147650514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Draobo.A"
        threat_id = "2147650514"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Draobo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 4b 45 59 5d 00 [0-4] 5b 2f 4b 45 59 5d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 25 00 73 00 25 00 73 00 2a 00 2e 00 2a 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 20 ff 37 ff 76 40 ff 50 3c 83 c7 04 4b 75 eb ff 76 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

