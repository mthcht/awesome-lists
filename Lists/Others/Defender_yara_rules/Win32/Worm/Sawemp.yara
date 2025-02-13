rule Worm_Win32_Sawemp_A_2147652794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sawemp.A"
        threat_id = "2147652794"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sawemp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pesene_seng_gawe.htm" wide //weight: 1
        $x_1_2 = "VBWG Infected" wide //weight: 1
        $x_1_3 = "Kebenaran" ascii //weight: 1
        $x_1_4 = "by: rieysha</p>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

