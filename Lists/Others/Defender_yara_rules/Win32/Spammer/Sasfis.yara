rule Spammer_Win32_Sasfis_A_2147628791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Sasfis.A"
        threat_id = "2147628791"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Sasfis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HAVE GOOD ACC letter" ascii //weight: 2
        $x_2_2 = "%04x%08.8lx$%08.8lx$%08x@%s" ascii //weight: 2
        $x_2_3 = "get_mx_records=" ascii //weight: 2
        $x_2_4 = "Errconn" ascii //weight: 2
        $x_2_5 = "Errrecv" ascii //weight: 2
        $x_2_6 = "R:0helo?" ascii //weight: 2
        $x_2_7 = "Parse RCPT/MAIL FROM/DATA_DATA/other" ascii //weight: 2
        $x_2_8 = "/cgi-bin/mcs.cgi" ascii //weight: 2
        $x_1_9 = "\\MSProtocol.cpp" ascii //weight: 1
        $x_1_10 = "\\wship6" ascii //weight: 1
        $x_1_11 = "mxs.mail.ru" ascii //weight: 1
        $x_1_12 = "g.mx.mail.yahoo.com" ascii //weight: 1
        $x_1_13 = "smtp.gmail.com" ascii //weight: 1
        $x_1_14 = "User-Agent: KMail/1.9.7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_2_*))) or
            (all of ($x*))
        )
}

