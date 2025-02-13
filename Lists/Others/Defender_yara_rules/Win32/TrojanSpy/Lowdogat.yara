rule TrojanSpy_Win32_Lowdogat_A_2147610066_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lowdogat.A"
        threat_id = "2147610066"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lowdogat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WlxLoggedOutSAS" ascii //weight: 1
        $x_1_2 = {be 05 00 00 00 8a 14 01 88 10 40 4e 75 f7}  //weight: 1, accuracy: High
        $x_1_3 = {74 37 8b d6 33 c9 81 ea 1c 30 00 10 8a 84 0a 1c 30 00 10 8a 99 1c 30 00 10 3a c3 75 1c 41 83 f9 04 7c e9}  //weight: 1, accuracy: High
        $x_1_4 = {75 0b 5f 33 c0 5e 81 c4 08 01 00 00 c3 81 ff 88 13 00 00 76 0b 8d 4c 24 0c 51 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

