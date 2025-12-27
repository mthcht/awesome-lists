rule Backdoor_Win32_HappyFuse_A_2147957196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/HappyFuse.A!dha"
        threat_id = "2147957196"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "HappyFuse"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 75 74 65 78 5f 4c 6f 63 61 6c 5f 57 69 6e 64 6f 77 73 5f}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 75 74 65 78 5f 4c 6f 63 61 6c 5f [0-36] 5f 57 69 6e 64 6f 77 73}  //weight: 1, accuracy: Low
        $x_5_3 = "WinHTTP Example/1.0" wide //weight: 5
        $x_5_4 = "Content-Type: application/x-www-form-urlencoded\\r\\nAPI-INDEX: %d\\r\\nAccept-Connect: %d" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

