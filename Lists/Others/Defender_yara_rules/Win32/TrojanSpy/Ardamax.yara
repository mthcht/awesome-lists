rule TrojanSpy_Win32_Ardamax_W_2147642918_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ardamax.W"
        threat_id = "2147642918"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ardamax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {41 4b 4c 2e 30 30 ?? 00}  //weight: 50, accuracy: Low
        $x_1_2 = {d1 e8 40 8d 71 14 3b c2 72 05 b8 04 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {83 f8 12 74 18 83 f8 5b 74 13 83 f8 10 74 0e 83 f8 11 74 09 83 f8 5c 74 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

