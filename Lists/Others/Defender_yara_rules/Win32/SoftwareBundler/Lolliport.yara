rule SoftwareBundler_Win32_Lolliport_198820_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Lolliport"
        threat_id = "198820"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolliport"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "user32::LoadImage(i 0, ts, i 0, i0, i0, i0x0010) i.r0" ascii //weight: 1
        $x_1_2 = "lollipop-network.com/eula.php?lg=" ascii //weight: 1
        $x_1_3 = "open http://www.lollipop-network.com/privacy.php?lg=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

