rule BrowserModifier_Win32_WurldMedia_14729_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/WurldMedia"
        threat_id = "14729"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "WurldMedia"
        severity = "27"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "toolbar=no,location=no,directories=no,menubar=no,scrollbars=no,resizable=no,fullscreen=no" ascii //weight: 3
        $x_1_2 = "werule" ascii //weight: 1
        $x_2_3 = "UpdateWhen" ascii //weight: 2
        $x_5_4 = "http://ins.rdxrp.com/stats/" ascii //weight: 5
        $x_1_5 = ";Platform=" ascii //weight: 1
        $x_1_6 = ";Minor=" ascii //weight: 1
        $x_1_7 = ";Major=" ascii //weight: 1
        $x_1_8 = ";RedirVers=" ascii //weight: 1
        $x_2_9 = "menubad" ascii //weight: 2
        $x_2_10 = "menugood" ascii //weight: 2
        $x_1_11 = "menudefault" ascii //weight: 1
        $x_1_12 = "mgrcode" ascii //weight: 1
        $x_3_13 = "/rmitop" ascii //weight: 3
        $x_3_14 = "/rmivars" ascii //weight: 3
        $x_3_15 = "www.rdxrp.com" ascii //weight: 3
        $x_3_16 = "www.rdxrs.com" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*) and 3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((5 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

