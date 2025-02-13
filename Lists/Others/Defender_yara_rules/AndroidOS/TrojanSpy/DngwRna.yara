rule TrojanSpy_AndroidOS_DngwRna_A_2147770354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/DngwRna.A!MTB"
        threat_id = "2147770354"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "DngwRna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LastSMSInboxReadTime" ascii //weight: 1
        $x_1_2 = {06 6f 64 72 2e 6f 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {06 63 6e 67 2e 63 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = "-gbwrhty" ascii //weight: 1
        $x_1_5 = "-smtrtxcb" ascii //weight: 1
        $x_1_6 = "-gcmapcr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

