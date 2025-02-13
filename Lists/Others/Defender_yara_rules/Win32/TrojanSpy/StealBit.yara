rule TrojanSpy_Win32_StealBit_A_2147896997_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/StealBit.A"
        threat_id = "2147896997"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "StealBit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 61 73 73 77 6f 72 64 00 00 00 00 53 54 41 54 49 43 00 00 45 44 49 54 00 00 00 00 4f 4b 00 00 42 55 54 54 4f 4e 00 00 43 61 6e 63 65 6c 00 ?? 45 00 6e 00 74 00 65 00 72 00 20 00 79 00 6f 00 75 00 72 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

