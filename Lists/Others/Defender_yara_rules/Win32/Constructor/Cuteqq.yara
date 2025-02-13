rule Constructor_Win32_Cuteqq_2147649496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Constructor:Win32/Cuteqq"
        threat_id = "2147649496"
        type = "Constructor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cuteqq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Http://Www.CuteQq.Cn" ascii //weight: 3
        $x_4_2 = "var Orh2=window[\"Math\"][\"random\"]()*rRaGEykU1;" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

