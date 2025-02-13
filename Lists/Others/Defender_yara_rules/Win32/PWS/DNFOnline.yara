rule PWS_Win32_DNFOnline_A_2147641304_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/DNFOnline.A"
        threat_id = "2147641304"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "DNFOnline"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 b2 27 00 00 53 68 01 02 00 00 ff 35 ?? ?? 40 00 ff 15 ?? ?? 40 00 6a 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f6 56 ff 35 ?? ?? 40 00 ff 15 ?? ?? 40 00 6a 03 56 56 56 56 6a 01 ff 35 ?? ?? 40 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = "dimepassmem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

