rule Worm_Win32_Shreptaz_A_2147633379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Shreptaz.A"
        threat_id = "2147633379"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Shreptaz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 ec 44 04 00 00 c6 45 d8 63 c6 45 d9 72 c6 45 da 61 c6 45 db 73 c6 45 dc 68 c6 45 dd 72 c6 45 de 65}  //weight: 2, accuracy: High
        $x_1_2 = "attrib +r +s +h crashreport.exe" ascii //weight: 1
        $x_1_3 = "bit.ly/4NF9KJ" ascii //weight: 1
        $x_1_4 = "tinyurl.com/n2anvs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

