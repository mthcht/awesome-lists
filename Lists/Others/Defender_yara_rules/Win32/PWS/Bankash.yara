rule PWS_Win32_Bankash_2147574902_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Bankash"
        threat_id = "2147574902"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Bankash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dummypostforsuperbat" ascii //weight: 2
        $x_1_2 = "Windows Security Alert" ascii //weight: 1
        $x_1_3 = "Hidden Process Requests Network Access" ascii //weight: 1
        $x_1_4 = "Allow all activities for this application" ascii //weight: 1
        $x_1_5 = "clearPwd(" ascii //weight: 1
        $x_1_6 = "westpac." ascii //weight: 1
        $x_1_7 = "*.eml" ascii //weight: 1
        $x_1_8 = "kaspersky" ascii //weight: 1
        $x_1_9 = "symantec" ascii //weight: 1
        $x_1_10 = "WNetEnumCachedPasswords" ascii //weight: 1
        $x_1_11 = "banking" ascii //weight: 1
        $x_1_12 = "citibank." ascii //weight: 1
        $x_1_13 = "\\etc\\hosts" ascii //weight: 1
        $x_1_14 = "POP3 Password" ascii //weight: 1
        $x_1_15 = "Manager\\Accounts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((12 of ($x_1_*))) or
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

