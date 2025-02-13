rule Worm_Win32_Bobax_A_2147582237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bobax.gen!A"
        threat_id = "2147582237"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bobax"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dr.Web" ascii //weight: 1
        $x_1_2 = "(%d)\"" ascii //weight: 1
        $x_1_3 = "FROM: <>" ascii //weight: 1
        $x_1_4 = "<IMG" ascii //weight: 1
        $x_1_5 = "%p: (%d) %s" ascii //weight: 1
        $x_1_6 = "Print Spooler Service" ascii //weight: 1
        $x_1_7 = "to registry: %s" ascii //weight: 1
        $x_1_8 = "server (%s)" ascii //weight: 1
        $x_2_9 = "EHLO localhost" ascii //weight: 2
        $x_1_10 = "smtp-relay" ascii //weight: 1
        $x_1_11 = "-=_NextPart_%03d" ascii //weight: 1
        $x_1_12 = "%s: send error" ascii //weight: 1
        $x_2_13 = "c|cpp|nfo|info|h" ascii //weight: 2
        $x_1_14 = "USER %s" ascii //weight: 1
        $x_1_15 = "PASS %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_2_*) and 11 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Bobax_B_2147582238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bobax.gen!B"
        threat_id = "2147582238"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bobax"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mailin-0%d.m" ascii //weight: 2
        $x_2_2 = "RCPT TO: <" ascii //weight: 2
        $x_2_3 = "MAIL FROM: <" ascii //weight: 2
        $x_1_4 = "Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_2_5 = "-=_NextPart_%03d" ascii //weight: 2
        $x_2_6 = "RND_DIGIT" ascii //weight: 2
        $x_2_7 = "RND_FROM_DOMAIN" ascii //weight: 2
        $x_2_8 = "smtprelay" ascii //weight: 2
        $x_2_9 = "toemail" ascii //weight: 2
        $x_2_10 = "fromemail" ascii //weight: 2
        $x_1_11 = "localhost/exe.exe" ascii //weight: 1
        $x_1_12 = "FirewallOverride" ascii //weight: 1
        $x_1_13 = "FirewallDisableNotify" ascii //weight: 1
        $x_1_14 = "AntiVirusOverride" ascii //weight: 1
        $x_1_15 = "AntiVirusDisableNotify" ascii //weight: 1
        $x_1_16 = "SOFTWARE\\Microsoft\\Security Center" ascii //weight: 1
        $x_1_17 = "firewall set" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_2_*))) or
            (all of ($x*))
        )
}

