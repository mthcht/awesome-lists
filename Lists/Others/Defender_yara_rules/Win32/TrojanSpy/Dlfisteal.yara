rule TrojanSpy_Win32_Dlfisteal_2147729215_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Dlfisteal"
        threat_id = "2147729215"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dlfisteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4folkoptions.info" ascii //weight: 1
        $x_1_2 = {3a 5c 55 73 65 72 73 5c 46 6c 79 33 31 31 30 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 69 6e 73 74 61 6c 6c 65 72 32 5f 32 30 31 37 5c 52 65 6c 65 61 73 65 5c 66 69 6e 64 65 72 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 46 69 6e 64 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

