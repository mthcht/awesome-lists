rule Virus_Win32_Evaman_2147555597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Evaman"
        threat_id = "2147555597"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Evaman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MyNameIsEva" ascii //weight: 2
        $x_1_2 = "\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "\\Internet Account Manager\\Accounts" ascii //weight: 1
        $x_1_4 = "aeioubcdfghjklmnpqrstvwxyz" ascii //weight: 1
        $x_1_5 = "InternetGetConnectedState" ascii //weight: 1
        $x_2_6 = "http://email.people.yahoo.com:80/py/psSearch.py?FirstName=" ascii //weight: 2
        $x_1_7 = "Patricia@" ascii //weight: 1
        $x_1_8 = "----=_NextPart_%c_%c_%d_%c_%c_" ascii //weight: 1
        $x_1_9 = "mx.%s" ascii //weight: 1
        $x_1_10 = "smtp.mail.%s" ascii //weight: 1
        $x_1_11 = "DnsQuery_A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

