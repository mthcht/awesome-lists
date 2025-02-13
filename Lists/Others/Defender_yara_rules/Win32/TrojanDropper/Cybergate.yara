rule TrojanDropper_Win32_Cybergate_MR_2147759080_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cybergate.MR"
        threat_id = "2147759080"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cybergate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6d 64 20 2f 63 20 3c 6e 75 6c 20 73 65 74 20 2f 70 20 3d 22 4d 22 20 3e 20 6c 73 61 73 73 2e 63 6f 6d 20 26 20 74 79 70 65 [0-8] 2e 63 6f 6d 20 3e 3e 20 6c 73 61 73 73 2e 63 6f 6d 20 26 20 64 65 6c [0-8] 2e 63 6f 6d 20 26 20 63 65 72 74 75 74 69 6c 20 2d 64 65 63 6f 64 65 [0-8] 2e 63 6f 6d 20 52 20 26 20 6c 73 61 73 73 2e 63 6f 6d 20 52 20 26 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

