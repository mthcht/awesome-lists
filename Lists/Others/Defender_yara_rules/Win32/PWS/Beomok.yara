rule PWS_Win32_Beomok_A_2147621665_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Beomok.A"
        threat_id = "2147621665"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Beomok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s?i=%s&o=%d" ascii //weight: 1
        $x_1_2 = "<pass>%s" ascii //weight: 1
        $x_1_3 = {b8 48 01 00 c0 c2 10 00 a1 ?? ?? ?? ?? 8d 54 24 04 cd 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {83 e8 05 89 46 01 c6 06 e9 a1}  //weight: 1, accuracy: High
        $x_1_5 = {88 1c 0f 7c c2 83 a1 00 01 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

