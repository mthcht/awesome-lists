rule Worm_Win32_Cipush_A_2147691085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cipush.A"
        threat_id = "2147691085"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cipush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "YahooBuddyMain" wide //weight: 1
        $x_1_2 = "autorun.inf" wide //weight: 1
        $x_1_3 = "[PageUp]" wide //weight: 1
        $x_1_4 = "%spam%" wide //weight: 1
        $x_1_5 = "klog" wide //weight: 1
        $x_1_6 = "seourl" wide //weight: 1
        $x_1_7 = "ussyClose" ascii //weight: 1
        $x_1_8 = {00 64 00 75 00 6d 00 70 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 [0-79] 00 66 00 61 00 63 00 65 00 62 00 6f 00 6f 00 6b 00 2e 00 63 00 6f 00 6d 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

