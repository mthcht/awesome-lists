rule Backdoor_Win32_Dradkiter_A_2147706507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dradkiter.A"
        threat_id = "2147706507"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dradkiter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "mobBotkiller" ascii //weight: 4
        $x_4_2 = "x.com/s/vbnt8gud1d14zx8/avkplugin.bin" wide //weight: 4
        $x_1_3 = "modKUAC" ascii //weight: 1
        $x_1_4 = "modMagicMutex" ascii //weight: 1
        $x_1_5 = "Anti_Disablers" ascii //weight: 1
        $x_1_6 = "BotkillerTimer" ascii //weight: 1
        $x_1_7 = "SpreadersTimer" ascii //weight: 1
        $x_1_8 = "#EOF DARKCOMET DATA --" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 5 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

