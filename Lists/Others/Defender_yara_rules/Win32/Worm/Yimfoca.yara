rule Worm_Win32_Yimfoca_A_2147643583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Yimfoca.gen!A"
        threat_id = "2147643583"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Yimfoca"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "aim:goim?screenname=%s&message=%s" ascii //weight: 1
        $x_1_2 = "explorer.exe http://browseusers.myspace.com/Browse/Browse.aspx" ascii //weight: 1
        $x_1_3 = "/ajax/chat/send.php?__a=1" ascii //weight: 1
        $x_1_4 = "%s\\wintybrd" ascii //weight: 1
        $x_3_5 = {83 7d f4 07 73 1b 8b 45 fc 03 45 f8 8b 4d f4 8a 00 32 81 ?? ?? ?? ?? 8b 4d fc 03 4d f8 88 01 eb d8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Yimfoca_B_2147646102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Yimfoca.gen!B"
        threat_id = "2147646102"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Yimfoca"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\windows\\nvsvc32.exe" ascii //weight: 1
        $x_1_2 = "*:Enabled:NVIDIA driver monitor" ascii //weight: 1
        $x_1_3 = "netsh firewall add allowedprogram 1.exe 1 ENABLE" ascii //weight: 1
        $x_1_4 = "explorer.exe http://browseusers.myspace.com/Browse/Browse.aspx" ascii //weight: 1
        $x_1_5 = "net stop wuauserv" ascii //weight: 1
        $x_1_6 = "visibility=false&post_form_id=" ascii //weight: 1
        $x_1_7 = "Ping Timeout? (%d-%d)%d/%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

