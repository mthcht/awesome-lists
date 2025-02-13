rule Spammer_Win32_Campsafe_2147607504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Campsafe"
        threat_id = "2147607504"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Campsafe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{rcpt_to}" ascii //weight: 1
        $x_1_2 = "{mail_from}" ascii //weight: 1
        $x_1_3 = "{ext_ip}" ascii //weight: 1
        $x_1_4 = "{mf_domain}" ascii //weight: 1
        $x_1_5 = "HELO {MYSERVER}" ascii //weight: 1
        $x_1_6 = "MAIL FROM:<{MAIL_FROM}>" ascii //weight: 1
        $x_1_7 = "RCPT TO:<{MAIL_TO}>" ascii //weight: 1
        $x_1_8 = "%d.%d.%d.%d.in-addr.arpa" ascii //weight: 1
        $x_1_9 = "gnReconnectionLimitMX" ascii //weight: 1
        $x_1_10 = "gnDnsAnswerTimeOut" ascii //weight: 1
        $x_1_11 = "gnDelay25" ascii //weight: 1
        $x_1_12 = "[%d.%d.%d.%d]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

