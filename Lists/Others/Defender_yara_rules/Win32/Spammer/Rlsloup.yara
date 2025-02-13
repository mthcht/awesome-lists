rule Spammer_Win32_Rlsloup_A_2147574511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Rlsloup.A"
        threat_id = "2147574511"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Rlsloup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "netsh firewall delete allowedprogram \"%s" ascii //weight: 2
        $x_2_2 = "netsh firewall add allowedprogram \"%s" ascii //weight: 2
        $x_2_3 = "Software\\Microsoft\\Internet Explorer\\Security" ascii //weight: 2
        $x_2_4 = "ip address like helo" ascii //weight: 2
        $x_2_5 = "it is you again :-(" ascii //weight: 2
        $x_2_6 = "evil_bounce" ascii //weight: 2
        $x_2_7 = "/bn/comgate.xhtml?" ascii //weight: 2
        $x_1_8 = "Content-Type: %s" ascii //weight: 1
        $x_1_9 = "Current IP Address:" ascii //weight: 1
        $x_1_10 = "Host: checkip.dyndns.org" ascii //weight: 1
        $x_1_11 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET" ascii //weight: 1
        $x_1_12 = "POST %s HTTP/1.1" ascii //weight: 1
        $x_1_13 = "data: i/o error" ascii //weight: 1
        $x_1_14 = "rcpt to: i/o error" ascii //weight: 1
        $x_1_15 = "mail from: i/o error" ascii //weight: 1
        $x_1_16 = "OK. Got %d ips" ascii //weight: 1
        $x_1_17 = "Email: <%s>" ascii //weight: 1
        $x_1_18 = "Session started (v=%d %s; cmpg: %s)" ascii //weight: 1
        $x_1_19 = "out-sessions.log" ascii //weight: 1
        $x_1_20 = "mail.ru" ascii //weight: 1
        $x_1_21 = "G/m=%d, T=%d, G=%d, B=%d (bl=%d, nouser=%d, nomx=%d, ioerr=%d, err=%d), th=%d" ascii //weight: 1
        $x_1_22 = "{rndabc8}" ascii //weight: 1
        $x_1_23 = "postmaster@usa.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 16 of ($x_1_*))) or
            ((4 of ($x_2_*) and 14 of ($x_1_*))) or
            ((5 of ($x_2_*) and 12 of ($x_1_*))) or
            ((6 of ($x_2_*) and 10 of ($x_1_*))) or
            ((7 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Rlsloup_A_2147574511_1
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Rlsloup.A"
        threat_id = "2147574511"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Rlsloup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $n_100_1 = "\\Simply Super Software\\Trojan Remover\\" ascii //weight: -100
        $x_10_2 = "smtp-client-rls.dll" ascii //weight: 10
        $x_1_3 = "DeviceIoControl" ascii //weight: 1
        $x_1_4 = "DeleteFileA" ascii //weight: 1
        $x_1_5 = "GetTickCount" ascii //weight: 1
        $x_1_6 = "CoCreateGuid" ascii //weight: 1
        $x_1_7 = "FindFirstFileA" ascii //weight: 1
        $x_1_8 = "update_load" ascii //weight: 1
        $x_1_9 = "GetMailslotInfo" ascii //weight: 1
        $x_1_10 = "WS2_32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Rlsloup_B_2147616454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Rlsloup.B"
        threat_id = "2147616454"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Rlsloup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 72 59 75 6a 0f be 44 3e 01 50 e8 ?? ?? 00 00 83 f8 63 59 75 59 0f be 44 3e 02 50 e8 ?? ?? 00 00 83 f8 70}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 06 ff d8 ff e0 8d 46 04 c7 00 00 10 4a 46 83 c0 04 c7 00 49 46 00 01 89 48 04}  //weight: 1, accuracy: High
        $x_1_3 = {74 16 8b 44 24 0c 8b 4c 24 04 8a 11 f6 d2 88 10 40 41 ff 4c 24 08 75 f2}  //weight: 1, accuracy: High
        $x_1_4 = "/bn/comgate.xhtml?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

