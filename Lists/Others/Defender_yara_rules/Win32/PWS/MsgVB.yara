rule PWS_Win32_MsgVB_2147583742_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/MsgVB"
        threat_id = "2147583742"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "MsgVB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "MSNMessenger" ascii //weight: 5
        $x_5_2 = "SendMimeConnect" ascii //weight: 5
        $x_5_3 = "If wVersion = 257 then everything is kewl" wide //weight: 5
        $x_5_4 = "E-Mail with Attachments!" ascii //weight: 5
        $x_5_5 = "Subjekt" ascii //weight: 5
        $x_5_6 = "Victim's Password" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

