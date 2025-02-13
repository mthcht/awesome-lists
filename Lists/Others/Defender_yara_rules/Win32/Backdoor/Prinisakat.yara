rule Backdoor_Win32_Prinisakat_A_2147645148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Prinisakat.A"
        threat_id = "2147645148"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Prinisakat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 6c 6f 6f 70 [0-4] 64 65 6c 20 25 73 [0-4] 69 66 20 65 78 69 73 74 20 25 73 20 67 6f 74 6f 20 6c 6f 6f 70}  //weight: 1, accuracy: Low
        $x_1_2 = "/search.html?ip=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

