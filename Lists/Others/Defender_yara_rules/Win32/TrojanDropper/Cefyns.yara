rule TrojanDropper_Win32_Cefyns_B_2147615640_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Cefyns.B"
        threat_id = "2147615640"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Cefyns"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d0 07 72 06 66 81 45 ?? 30 f8 8d 85 64 ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {72 0e 8a 08 80 f9 ?? 74 07 80 f1 ?? 88 08 eb e7}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 85 6c fd ff ff 54 ff d3 50 8d 85 64 fe ff ff 50 6a 01}  //weight: 1, accuracy: High
        $x_1_4 = {5c 6e 76 73 76 63 31 30 32 34 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

