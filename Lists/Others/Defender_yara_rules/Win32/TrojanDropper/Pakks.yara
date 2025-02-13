rule TrojanDropper_Win32_Pakks_A_2147614122_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Pakks.A"
        threat_id = "2147614122"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Pakks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 bb 41 00 00 00 b9 ?? ?? 00 00 bf ?? ?? 40 00 89 fe e8 ?? ?? ff ff 68 ?? ?? 40 00 6a 00 68 01 00 1f 00 ff d3 85 c0 0f 85 ?? ?? ff ff e8 0d 00 00 00 61 64 76 61 70 69 33 32 2e 64 6c 6c 00 ff 56 14 89 46 18 ff 36 68 8e 4e 0e ec ff d7 e8 0d 00 00 00 61 64 76 61 70 69 33 32 2e 64 6c 6c 00 ff d3 ff 36 68 33 ca 8a 5b ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {00 66 75 63 6b 79 6f 75 00 63 6d 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

