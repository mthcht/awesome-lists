rule Worm_Win32_Nerphun_A_2147652681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nerphun.gen!A"
        threat_id = "2147652681"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nerphun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PharOlniNe\\Proyecto1.vbp" wide //weight: 1
        $x_1_2 = "DeclararFun" ascii //weight: 1
        $x_1_3 = "MsnSpreader" ascii //weight: 1
        $x_1_4 = "Hey !! mira esta postal que encontre para ti :$ http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

