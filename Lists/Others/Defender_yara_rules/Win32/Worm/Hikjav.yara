rule Worm_Win32_Hikjav_A_2147618330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hikjav.A"
        threat_id = "2147618330"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hikjav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 44 24 10 63 c7 44 24 14 ?? ?? ?? ?? 8a 44 24 10 be ?? ?? ?? ?? 8d 7c 24 0c 66 a5 a4 88 44 24 0c 8d 44 24 0c 50 ff d3 83 f8 02 74 21 8d 44 24 0c 50 ff d3 83 f8 03 74 15}  //weight: 1, accuracy: Low
        $x_1_2 = "%c:\\autorun.inf" ascii //weight: 1
        $x_1_3 = "%c:\\RECYCLER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

