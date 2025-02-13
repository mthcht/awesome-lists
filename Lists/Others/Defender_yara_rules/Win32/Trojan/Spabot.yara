rule Trojan_Win32_Spabot_A_2147604729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spabot.gen!A"
        threat_id = "2147604729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spabot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "spambot" ascii //weight: 50
        $x_50_2 = "MAIL FROM: <%s>" ascii //weight: 50
        $x_50_3 = "RCPT TO:<%s>" ascii //weight: 50
        $x_50_4 = "http://autoescrowpay.com/s.php" ascii //weight: 50
        $x_50_5 = "MJV:%d MNV:%d PID:%d Build:%d Comment:%s" ascii //weight: 50
        $x_50_6 = {2e 63 6f 6d 00 [0-80] 2e 63 6f 6d 00 [0-80] 2e 63 6f 6d 00 [0-80] 2e 63 6f 6d 00 [0-80] 2e 63 6f 6d 00}  //weight: 50, accuracy: Low
        $x_5_7 = "AOL 7.0 for Windows" ascii //weight: 5
        $x_5_8 = "Calypso Version" ascii //weight: 5
        $x_5_9 = "eGroups Message Poster" ascii //weight: 5
        $x_5_10 = "Internet Mail Service (5.5.2650.21)" ascii //weight: 5
        $x_5_11 = "MailGate v3.0" ascii //weight: 5
        $x_5_12 = "MIME-tools 4.104 (Entity 4.116)" ascii //weight: 5
        $x_5_13 = "Mutt/1.5.1i" ascii //weight: 5
        $x_5_14 = "Pegasus Mail for Win32 (v2.53/R1)" ascii //weight: 5
        $x_5_15 = "PObox II beta1.0" ascii //weight: 5
        $x_5_16 = "QUALCOMM Windows Eudora" ascii //weight: 5
        $x_5_17 = "SmartMailer Version 1.56 -German Privat License-" ascii //weight: 5
        $x_5_18 = "Sylpheed version 0.8.2 (GTK+ 1.2.10; i586-alt-linux)" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_50_*) and 10 of ($x_5_*))) or
            ((4 of ($x_50_*))) or
            (all of ($x*))
        )
}

