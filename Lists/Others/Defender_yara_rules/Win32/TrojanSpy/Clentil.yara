rule TrojanSpy_Win32_Clentil_2147653191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Clentil"
        threat_id = "2147653191"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Clentil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/client.html" ascii //weight: 2
        $x_1_2 = "&cm[%d]=Outlook" ascii //weight: 1
        $x_1_3 = "&cm[%d]=TheBat" ascii //weight: 1
        $x_1_4 = "&src[%d]=emailgrabber_%s" ascii //weight: 1
        $x_1_5 = "&src[%d]=ftpgrabber_%s" ascii //weight: 1
        $x_1_6 = "FTPDetector" ascii //weight: 1
        $x_1_7 = "&query=sniff&data=" ascii //weight: 1
        $x_1_8 = "##BOT_ID_EXIST###yes###BOT_ID_EXIST_END###" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

