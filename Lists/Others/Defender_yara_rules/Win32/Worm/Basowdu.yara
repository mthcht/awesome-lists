rule Worm_Win32_Basowdu_A_2147653842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Basowdu.A"
        threat_id = "2147653842"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Basowdu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "@mail.ru#smtp.mail.ru#" ascii //weight: 2
        $x_2_2 = "sstm\\cdpath.txt" ascii //weight: 2
        $x_1_3 = "mouseup" ascii //weight: 1
        $x_1_4 = "getimg" ascii //weight: 1
        $x_1_5 = "blockdata" ascii //weight: 1
        $x_1_6 = "getlog" ascii //weight: 1
        $x_1_7 = "sstmemail" ascii //weight: 1
        $x_1_8 = "decod C:\\" ascii //weight: 1
        $x_1_9 = "coderupd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

