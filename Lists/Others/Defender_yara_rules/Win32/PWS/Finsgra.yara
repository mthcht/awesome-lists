rule PWS_Win32_Finsgra_A_2147616326_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Finsgra.A"
        threat_id = "2147616326"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Finsgra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 45 fc 41 3a 5c 00 ff 90 01 04 a3 ?? ?? ?? ?? c6 45 fc 41 8d 45 fc 50 a1 ?? ?? ?? ?? ff 39 ?? ?? 00 00 85 c0 74 18}  //weight: 5, accuracy: Low
        $x_5_2 = {8a c8 80 e9 21 80 f9 5d 77 58 3c 20 74 54 3c 22}  //weight: 5, accuracy: High
        $x_5_3 = {7e 79 8d 3c 02 8d 41 ff 6a 44 33 d2 59 f7 f1 8b f0 46 33 c0 8b d7 8a 0a 3a cb 88 8c 05 ?? ?? ?? ?? 74 08 42 42 40 83 f8 44 7e eb}  //weight: 5, accuracy: Low
        $x_1_4 = "//M%u/sniffGrabFileName" ascii //weight: 1
        $x_1_5 = "//M%u/diskGrabFileName" ascii //weight: 1
        $x_1_6 = "//M%u/lastSniffReport" ascii //weight: 1
        $x_1_7 = "MAIL=\\W*([A-Za-z0-9-_\\.]+@[A-Za-z0-9-_\\.]+\\.[A-Za-z]+)" ascii //weight: 1
        $x_1_8 = "=\\W*([A-Za-z0-9-_\\.]+@[A-Za-z0-9-_\\.]+\\.[A-Za-z]+)\\)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

