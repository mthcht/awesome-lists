rule TrojanSpy_Win32_Wytexu_A_2147623069_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Wytexu.A"
        threat_id = "2147623069"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wytexu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 48 6a ff 6a 00 68 b1 00 00 00 50 ff d6 8b 0d ?? ?? 40 00 6a 00 6a 00 68 01 03 00 00 51 ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 04 18 01 50 74 07 3d 04 18 21 50 75 c7 56 ff 15 ?? ?? 40 00 68 00 01 00 00 8d 4c 24 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

