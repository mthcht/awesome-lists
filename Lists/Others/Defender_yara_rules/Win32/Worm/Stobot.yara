rule Worm_Win32_Stobot_A_2147636467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Stobot.A"
        threat_id = "2147636467"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Stobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "irC_STO_Botnet_Module_Stable" ascii //weight: 3
        $x_2_2 = "udpfloodstart" ascii //weight: 2
        $x_2_3 = "m_deletebot_password_error" ascii //weight: 2
        $x_2_4 = "command_synflood" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

