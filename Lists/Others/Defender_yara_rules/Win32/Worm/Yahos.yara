rule Worm_Win32_Yahos_A_2147643965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Yahos.A"
        threat_id = "2147643965"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Yahos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6d 47 fe 74 e8 bf c2 45 90 35 d1 5e 33 0a 24 6d}  //weight: 5, accuracy: High
        $x_1_2 = "Invite your friends to Google Talk" ascii //weight: 1
        $x_1_3 = "%s:*:Enabled:%s" ascii //weight: 1
        $x_1_4 = "Blast IM" ascii //weight: 1
        $x_1_5 = "mira esta foto" wide //weight: 1
        $x_1_6 = "kil baxmaq" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

