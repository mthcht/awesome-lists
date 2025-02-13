rule Worm_Win32_Burnwoo_B_2147686432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Burnwoo.B"
        threat_id = "2147686432"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Burnwoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf 41 00 00 00 83 24 bd ?? ?? ?? ?? 00 47 83 ff 5a 7e f2 eb 38 e8 ?? ?? ?? ?? 83 f8 01 75 10}  //weight: 1, accuracy: Low
        $x_1_2 = ".%s/w.php?id=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

