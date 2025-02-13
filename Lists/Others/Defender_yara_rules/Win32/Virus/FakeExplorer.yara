rule Virus_Win32_FakeExplorer_A_2147608994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/FakeExplorer.A"
        threat_id = "2147608994"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeExplorer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 18 00 00 00 8b 40 34 0b c0 74 04 33 c0 c9 c3 8d 7d dc 57 c7 07 77 73 32 5f c7 47 04 33 32 2e 64 c7 47 08 6c 6c 00 12 e8 ?? ?? ?? ?? 0b c0 74 05 e8 ?? ?? ?? ?? 33 c0 c9 c3 60 e8 8a ff ff ff 61 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 00 47 45 54 20 c7 40 04 2f 00 00 00 50 ff 75 f8 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 ff 75 f8 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? c7 00 20 48 54 54 c7 40 04 50 2f 31 2e c7 40 08 31 0d 0a 55 c7 40 0c 73 65 72 2d c7 40 10 41 67 65 6e c7 40 14 74 3a 20 49 c7 40 18 6e 65 74 0d c7 40 1c 0a 48 6f 73 c7 40 20 74 3a 20 00 50 ff 75 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

