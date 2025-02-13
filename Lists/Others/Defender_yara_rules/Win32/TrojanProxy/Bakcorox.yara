rule TrojanProxy_Win32_Bakcorox_A_2147633130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Bakcorox.A"
        threat_id = "2147633130"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bakcorox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b e8 83 c4 04 68 ff 00 00 00 8d 54 24 24 b9 bb 01 00 00 52 66 89 4d 10}  //weight: 1, accuracy: High
        $x_1_2 = {c7 44 24 18 00 00 00 00 c7 44 24 1c 00 00 00 00 80 fb 61 74 38 80 fb 73 74 15}  //weight: 1, accuracy: High
        $x_1_3 = {50 72 6f 78 79 42 6f 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

