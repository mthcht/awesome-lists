rule Ransom_Win32_Trickbot_GO_2147751442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Trickbot.GO!MSR"
        threat_id = "2147751442"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "e6ZggaBC6pIyyNdA6y4DkIuzIxEXzrcTR" ascii //weight: 2
        $x_1_2 = "Your APDU is error!" ascii //weight: 1
        $x_1_3 = "PC/SC Reader/Card operation: Open/Close/Reset/Transmit." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

