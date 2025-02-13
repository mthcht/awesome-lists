rule TrojanSpy_Win32_Grump_A_2147627362_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Grump.A"
        threat_id = "2147627362"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Grump"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 00 61 00 76 00 70 00 2e 00 65 00 78 00 65 00 00 00 73 00 6e 00 73 00 6d 00 63 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 00 00 41 6c 20 53 74 61 72 74 20 31 00 00 46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 75 00 74 00 6f 00 20 00 73 00 65 00 74 00 75 00 70 00 00 00 46 69 72 65 77 61 6c 6c 20 61 75 74 6f 20 73 65 74 75 70 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 68 6f 73 74}  //weight: 1, accuracy: High
        $x_1_2 = "InstallRootkit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

