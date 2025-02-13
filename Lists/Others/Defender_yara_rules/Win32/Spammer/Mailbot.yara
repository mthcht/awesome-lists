rule Spammer_Win32_Mailbot_Q_2147574512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Mailbot.Q"
        threat_id = "2147574512"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Mailbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d b7 00 00 00 75 1b 83 ec 0c}  //weight: 1, accuracy: High
        $x_1_2 = "%s:*:Enabled:Server" ascii //weight: 1
        $x_1_3 = "Profile\\AuthorizedApplications\\List" ascii //weight: 1
        $x_1_4 = "MAIL FROM:%s" ascii //weight: 1
        $x_1_5 = "RCPT TO:%s" ascii //weight: 1
        $x_1_6 = "To: %TO_EMAIL" ascii //weight: 1
        $x_1_7 = "Content-Type: %CONTENT_TYPE; charset=us-ascii" ascii //weight: 1
        $x_1_8 = "%s, %d %s %d %.2d:%.2d:%.2d %.4d" ascii //weight: 1
        $x_1_9 = "<%s@%s>" ascii //weight: 1
        $x_1_10 = "----=_NextPart_%.3X_0%.3X_%.8X.%.8X" ascii //weight: 1
        $x_1_11 = "badcab1e" ascii //weight: 1
        $x_1_12 = "realhelo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Spammer_Win32_Mailbot_K_2147600323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Mailbot.K"
        threat_id = "2147600323"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Mailbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "MAIL FROM" ascii //weight: 1
        $x_1_3 = "RCPT TO" ascii //weight: 1
        $x_1_4 = "helperubfl.exe" ascii //weight: 1
        $x_1_5 = "ubfl.exe" ascii //weight: 1
        $x_1_6 = "updateubfl.exe" ascii //weight: 1
        $x_1_7 = "cbl.abuseat.org/lookup.cgi" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_9 = "CreateMutexA" ascii //weight: 1
        $x_1_10 = "HttpOpenRequestA" ascii //weight: 1
        $x_1_11 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

