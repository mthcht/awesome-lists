rule TrojanSpy_Win32_Hyek_A_2147650546_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hyek.A"
        threat_id = "2147650546"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hyek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 68 79 62 72 69 64 6c 6f 67 [0-16] 5c 6e 6f 6c 6f 67 67 65 72}  //weight: 1, accuracy: Low
        $x_1_2 = {64 79 62 61 72 74 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 53 79 73 41 64 6d 69 6e 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

