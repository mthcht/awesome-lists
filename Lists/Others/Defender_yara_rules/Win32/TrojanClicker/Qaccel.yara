rule TrojanClicker_Win32_Qaccel_A_2147717386_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Qaccel.A!bit"
        threat_id = "2147717386"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Qaccel"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DE622D185C1BC760E40CCDB249B95612" ascii //weight: 1
        $x_1_2 = {5c 51 51 41 63 63 65 6c 65 78 2e 65 78 65 [0-5] 5c 54 65 6e 63 65 6e 74}  //weight: 1, accuracy: Low
        $x_1_3 = "CWebBrowser2" ascii //weight: 1
        $x_1_4 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e [0-16] 2e 63 6f 6d 2f 3f 74 6e 3d 25 73 [0-32] 5f 68 61 6f 5f 70 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

