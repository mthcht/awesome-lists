rule TrojanSpy_Win32_Symcomder_D_2147679013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Symcomder.D"
        threat_id = "2147679013"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Symcomder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 44 65 6c 61 79 00 4b 65 79 62 6f 61 72 64 53 70 65 65 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {7b 43 6c 69 6b 7d 0d 0a 00 7b 42 61 63 6b 7d}  //weight: 1, accuracy: High
        $x_1_3 = "{CLIPBOARD END}" ascii //weight: 1
        $x_1_4 = {75 6e 5d 20 3e 3e 20 25 54 45 4d 50 25 5c [0-10] 2e 72 65 67 0d 0a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

