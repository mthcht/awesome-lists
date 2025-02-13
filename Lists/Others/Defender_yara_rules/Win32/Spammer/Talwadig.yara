rule Spammer_Win32_Talwadig_A_2147628082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Talwadig.A"
        threat_id = "2147628082"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Talwadig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Poshel-ka ti na hui drug aver" ascii //weight: 3
        $x_2_2 = "BOT_HOST" ascii //weight: 2
        $x_1_3 = "EHLO {MYSERVER}" ascii //weight: 1
        $x_1_4 = "{MAILTO_NAME} <{MAIL_TO}>" ascii //weight: 1
        $x_1_5 = "MAIL FROM:<{MAIL_FROM}>" ascii //weight: 1
        $x_1_6 = "RCPT TO: <{MAIL_TO}>" ascii //weight: 1
        $x_1_7 = "MAILFROM_" ascii //weight: 1
        $x_1_8 = "MAILTO_" ascii //weight: 1
        $x_1_9 = "TAGMAILFROM" ascii //weight: 1
        $x_1_10 = "ext_ip" ascii //weight: 1
        $x_1_11 = "FOR variable = 0 TO ATTACHCOUNT" ascii //weight: 1
        $x_1_12 = {52 4f 54 00 42 41 53 45 36 34}  //weight: 1, accuracy: High
        $x_1_13 = "mxs.mail.ru" ascii //weight: 1
        $x_1_14 = "gmail-smtp-in.l.google.com" ascii //weight: 1
        $x_1_15 = "mail7.digitalwaves.co.nz" ascii //weight: 1
        $x_1_16 = "read macroses." ascii //weight: 1
        $x_1_17 = "199.2.252.10" ascii //weight: 1
        $x_1_18 = "204.97.212.10" ascii //weight: 1
        $x_1_19 = "64.102.255.44" ascii //weight: 1
        $x_1_20 = "128.107.241.185" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((15 of ($x_1_*))) or
            ((1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

