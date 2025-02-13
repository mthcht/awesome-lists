rule Worm_MSIL_Rapzo_A_2147653795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Rapzo.A"
        threat_id = "2147653795"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rapzo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fuck_Uac" ascii //weight: 1
        $x_1_2 = "KBDLLHOOKSTRUCT" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Internet Explorer\\IntelliForms" wide //weight: 1
        $x_1_4 = "[DEL]" wide //weight: 1
        $x_1_5 = "select * from win32_share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

