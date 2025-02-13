rule Spammer_Win32_Darvec_A_2147652975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Darvec.A"
        threat_id = "2147652975"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Darvec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ip=%u|u=%s|p=%s|MailFrom=%s|From=%s|lag=%s" ascii //weight: 1
        $x_1_2 = "MUTEX_Mail_Plugin_v" ascii //weight: 1
        $x_1_3 = {53 4f 46 54 57 41 52 45 5c 53 65 63 75 72 69 74 79 00}  //weight: 1, accuracy: High
        $x_1_4 = {45 4e 00 00 43 4e 00 00 25 73 5c 25 73 00 00 00 63 6f 6e 66 69 67 2e 69 6e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

