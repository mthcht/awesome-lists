rule Spammer_Win32_Bagle_2147580902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Bagle"
        threat_id = "2147580902"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Bagle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "alreadyArial" ascii //weight: 1
        $x_1_2 = "filesys, filetxt, getname, path, textfile," ascii //weight: 1
        $x_1_3 = ".Write(chr(a(i)))" ascii //weight: 1
        $x_2_4 = "\" & vbcrlf" ascii //weight: 2
        $x_1_5 = "HELO %s.net" ascii //weight: 1
        $x_1_6 = "HELO %s.com" ascii //weight: 1
        $x_1_7 = "HELO %s.org" ascii //weight: 1
        $x_1_8 = "MAIL FROM:<%s>" ascii //weight: 1
        $x_1_9 = "RCPT TO:<%s>" ascii //weight: 1
        $x_1_10 = "@somewhere" ascii //weight: 1
        $x_1_11 = "From: \"%s\" <%s>" ascii //weight: 1
        $x_1_12 = "Subject: %s" ascii //weight: 1
        $x_1_13 = "Message-ID: <%s%s>" ascii //weight: 1
        $x_1_14 = "boundary=\"--------%s" ascii //weight: 1
        $x_1_15 = "Content-Type: %s; name=\"%s.%s" ascii //weight: 1
        $x_1_16 = "Content-Disposition: attachment; filename=\"%s.%s" ascii //weight: 1
        $x_1_17 = "<img src=\"cid:%s.%s\"><br>" ascii //weight: 1
        $x_1_18 = "Password: %s" ascii //weight: 1
        $x_1_19 = "Password - %s" ascii //weight: 1
        $x_1_20 = "Re: Msg" ascii //weight: 1
        $x_1_21 = "Re: Thank" ascii //weight: 1
        $x_1_22 = "Re: Document" ascii //weight: 1
        $x_1_23 = "Re: Incoming" ascii //weight: 1
        $x_1_24 = "RE: Message" ascii //weight: 1
        $x_1_25 = "Encrypted document" ascii //weight: 1
        $x_1_26 = "Read the attach.<br><br>" ascii //weight: 1
        $x_1_27 = "Your file is attached.<br><br>" ascii //weight: 1
        $x_1_28 = "details.<br><br>" ascii //weight: 1
        $x_1_29 = "file.<br><br>" ascii //weight: 1
        $x_1_30 = "<br>For security " ascii //weight: 1
        $x_1_31 = "password <img src=\"cid:%s.%s\">" ascii //weight: 1
        $x_1_32 = "Skynet" ascii //weight: 1
        $x_1_33 = "Zone Labs Client" ascii //weight: 1
        $x_1_34 = "Antivirus" ascii //weight: 1
        $x_1_35 = "Firewall Service" ascii //weight: 1
        $x_1_36 = "Tiny AV" ascii //weight: 1
        $x_1_37 = "SysMonXP" ascii //weight: 1
        $x_1_38 = "Norton " ascii //weight: 1
        $x_1_39 = "Kaspersky" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((32 of ($x_1_*))) or
            ((1 of ($x_2_*) and 30 of ($x_1_*))) or
            (all of ($x*))
        )
}

