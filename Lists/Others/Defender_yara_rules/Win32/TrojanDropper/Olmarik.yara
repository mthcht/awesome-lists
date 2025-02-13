rule TrojanDropper_Win32_Olmarik_C_2147651494_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Olmarik.C"
        threat_id = "2147651494"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Olmarik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 45 fc 3e 53 46 56 03 f1 8a 06 88 04 39 8b 45 fc 33 d2 b9 5f 32 00 00 f7 f1 89 45 fc 8a 45 08 88 06 eb}  //weight: 1, accuracy: High
        $x_1_2 = {8a 04 39 84 c0 74 09 3c 41 74 05 34 41 88 04 39 83 c1 08 3b ce 72 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

