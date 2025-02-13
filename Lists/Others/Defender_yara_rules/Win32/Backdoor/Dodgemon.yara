rule Backdoor_Win32_Dodgemon_A_2147597760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dodgemon.A"
        threat_id = "2147597760"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dodgemon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "shell\\open\\Command=sysboot.scr" ascii //weight: 2
        $x_2_2 = "%smove /Y \"%s\" \"%s\"" ascii //weight: 2
        $x_2_3 = "netsh firewall add portopening UDP %d" ascii //weight: 2
        $x_2_4 = "&hostname=%s&myip=%s" ascii //weight: 2
        $x_1_5 = "+OK %d %%d" ascii //weight: 1
        $x_1_6 = "/plain; charset=gbk" ascii //weight: 1
        $x_1_7 = "; filename=\"attachment1\"" ascii //weight: 1
        $x_1_8 = "MAIL FROM:<%s> BODY=8BITMIME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

