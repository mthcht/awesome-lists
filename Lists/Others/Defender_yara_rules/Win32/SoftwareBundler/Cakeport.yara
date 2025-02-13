rule SoftwareBundler_Win32_Cakeport_198789_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Cakeport"
        threat_id = "198789"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Cakeport"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "user32::LoadImage(i 0, ts, i 0, i0, i0, i0x0010) i.r0" ascii //weight: 1
        $x_1_2 = "getwebcake.com/Terms" ascii //weight: 1
        $x_1_3 = "open http://getwebcake.com/Privacy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

