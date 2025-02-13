rule TrojanClicker_Win32_ClickTrans_2147721045_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/ClickTrans"
        threat_id = "2147721045"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "ClickTrans"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "software\\mytransitguide" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 79 00 2e 00 70 00 63 00 6d 00 61 00 70 00 73 00 2e 00 6e 00 65 00 74 00 2f 00 61 00 70 00 69 00 2f 00 72 00 65 00 70 00 6f 00 72 00 74 00 3f 00 74 00 79 00 70 00 65 00 3d 00 [0-4] 26 00 63 00 6f 00 64 00 65 00 3d 00 4d 00 79 00 54 00 72 00 61 00 6e 00 73 00 69 00 74 00 47 00 75 00 69 00 64 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 2e 00 67 00 65 00 74 00 45 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 42 00 79 00 49 00 64 00 28 00 27 00 [0-255] 27 00 29 00 2e 00 63 00 6c 00 69 00 63 00 6b 00 28 00 29 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_4 = "Start Click ads!" wide //weight: 1
        $x_1_5 = "Click x = %d,y = %d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

