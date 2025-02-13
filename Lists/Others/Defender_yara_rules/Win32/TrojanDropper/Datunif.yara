rule TrojanDropper_Win32_Datunif_A_2147627294_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Datunif.A"
        threat_id = "2147627294"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Datunif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a9 f3 00 01 c1 e7 04 60 ff 9d fb 12 fc 0d}  //weight: 1, accuracy: High
        $x_1_2 = {f5 2e 00 00 00 04 38 ff 0a 04 00 08 00 04 38 ff fb ef 28 ff f5 62 00 00 00 04 18 ff 0a 04 00 08 00 04 18 ff fb ef 08 ff f5 61 00 00 00 04 f8 fe 0a 04 00 08 00 04 f8 fe fb ef e8 fe f5 74}  //weight: 1, accuracy: High
        $x_1_3 = {f5 64 00 00 00 04 4c ff 0a 04 00 08 00 04 4c ff fb ef 38 ff f5 65 00 00 00 04 28 ff 0a 04 00 08 00 04 28 ff fb ef 18 ff f5 6c 00 00 00 04 08 ff 0a 04 00 08 00 04 08 ff fb ef f8 fe f5 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

