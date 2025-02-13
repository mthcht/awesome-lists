rule TrojanSpy_Win32_Spyeks_A_2147603156_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Spyeks.A"
        threat_id = "2147603156"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyeks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 [0-18] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Computer Name:" wide //weight: 1
        $x_1_3 = "@Victim.com" wide //weight: 1
        $x_1_4 = "SpyEx Report" wide //weight: 1
        $x_1_5 = "software\\microsoft\\windows\\currentversion\\run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

