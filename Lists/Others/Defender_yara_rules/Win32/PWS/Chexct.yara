rule PWS_Win32_Chexct_A_2147658697_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Chexct.A"
        threat_id = "2147658697"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Chexct"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s?un=%s&pn=%s_%02d%02d%02d%02d_%d.jpg" ascii //weight: 1
        $x_1_2 = "?at=upm&" ascii //weight: 1
        $x_1_3 = {6a 40 6a 06 56 ff 15 ?? ?? ?? ?? 8b 45 0c c6 06 68 89 46 01 c6 46 05 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

