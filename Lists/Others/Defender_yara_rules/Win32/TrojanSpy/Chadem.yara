rule TrojanSpy_Win32_Chadem_A_2147803993_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Chadem.A"
        threat_id = "2147803993"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Chadem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 ff d6 66 3d 15 00 0f 85 ?? ?? 00 00 8b 15 ?? ?? ?? ?? 6a 02}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 44 24 18 50 68 01 00 00 98 56}  //weight: 1, accuracy: High
        $x_1_3 = "dm=%s&lg=%s&ps=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

