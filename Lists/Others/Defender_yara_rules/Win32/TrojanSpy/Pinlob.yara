rule TrojanSpy_Win32_Pinlob_A_2147619309_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pinlob.A"
        threat_id = "2147619309"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pinlob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 0d 0a 43 6f 6f 6b 69 65 3a 20 0d 0a 0d 0a 25 73 00 00 00 70 69 6e 3d 00 00 00 00 6a 62 73 3d 00 00 00 00 72 3d 00 00 6c 3d 00 00 73 3d 00 00 70 3d 00 00 26 00 00 00 75 3d 00 00 73 78 2f 6c 69 6e 2e 61 73 70 00 00 39 34 39 33 35 36 38 2e 6b 38 36 2e 6f 70 65 6e 73 72 73 2e 63 6e 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = {d4 da cf df 00 00 00 00 25 64 00 00 cf df 00 00 25 73 00 00 54 77 65 6c 76 65 53 74 6f 72 79 00 50 4f 53 54 20 2f 25 73 20 48 54 54 50 2f 31 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

