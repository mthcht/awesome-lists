rule HackTool_Win32_SmptMailStress_2147708595_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SmptMailStress"
        threat_id = "2147708595"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SmptMailStress"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Plese wait! Senting %d mails using %d Threads is started..." ascii //weight: 1
        $x_1_2 = "Sent %d th mail is failed trying next...." ascii //weight: 1
        $x_1_3 = "Sent %d th mail is success...." ascii //weight: 1
        $x_1_4 = "Hir's SMTP stress" ascii //weight: 1
        $x_1_5 = "Senting %d mails Completed!!! I am ready for Checking again !!!" ascii //weight: 1
        $x_1_6 = "I am ready for Checking Again!!!!!" ascii //weight: 1
        $x_2_7 = "microsoft [111.122.1.12]" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

