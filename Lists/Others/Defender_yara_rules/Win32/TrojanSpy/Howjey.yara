rule TrojanSpy_Win32_Howjey_A_2147618881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Howjey.A"
        threat_id = "2147618881"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Howjey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Windows Live Hoje" ascii //weight: 2
        $x_1_2 = "boundary=\"=_NextPart_2rfk" ascii //weight: 1
        $x_1_3 = "smtp.bra.terra.com.br" ascii //weight: 1
        $x_1_4 = "MSN2Timer" ascii //weight: 1
        $x_1_5 = "<<LINK1>>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

