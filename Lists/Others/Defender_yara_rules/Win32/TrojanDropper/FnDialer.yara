rule TrojanDropper_Win32_FnDialer_2147804048_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/FnDialer"
        threat_id = "2147804048"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "FnDialer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 74 74 65 72 6e 20 6e 6f 74 20 66 6f 75 6e 64 21 00 46 75 6e 63 74 69 6f 6e 20 6e 6f 74 20 66 6f 75 6e 64 21 00 49 6e 66 6f 00 66 6e 44 69 61 6c 65 72 44 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

