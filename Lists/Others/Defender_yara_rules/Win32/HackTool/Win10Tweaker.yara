rule HackTool_Win32_Win10Tweaker_2147810477_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Win10Tweaker"
        threat_id = "2147810477"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Win10Tweaker"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "m_IsRep0LongDecoders" ascii //weight: 1
        $x_1_2 = "m_IsRepG0Decoders" ascii //weight: 1
        $x_1_3 = "m_PosSlotDecoder" ascii //weight: 1
        $x_1_4 = "STAThreadAttribute" ascii //weight: 1
        $x_5_5 = "Win 10 Tweaker" ascii //weight: 5
        $x_5_6 = "Win_10_Tweaker.Form1.resources" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

