rule Backdoor_Win32_Dumador_2147555608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dumador"
        threat_id = "2147555608"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dumador"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\TEMP\\fa4537ef.tmp" ascii //weight: 2
        $x_1_2 = "===KEYLOGGER DATA END===" ascii //weight: 1
        $x_1_3 = "===KEYLOGGER DATA START===" ascii //weight: 1
        $x_1_4 = "*** Protected Storage Data ***" ascii //weight: 1
        $x_1_5 = "*** Protected Storage Data ends ***" ascii //weight: 1
        $x_2_6 = "drwxrwxrwx 1 0         @disk_X" ascii //weight: 2
        $x_1_7 = "]\\dvp.log" ascii //weight: 1
        $x_1_8 = "mailsended" ascii //weight: 1
        $x_2_9 = "<address@yandex.ru>" ascii //weight: 2
        $x_2_10 = "socks/bot/cmd.txt" ascii //weight: 2
        $x_1_11 = "\\rundlln.sys" ascii //weight: 1
        $x_2_12 = "\\TEMP\\fe43e701.htm" ascii //weight: 2
        $x_2_13 = "*** Far Manager passwords ***" ascii //weight: 2
        $x_2_14 = "[WebMoney ID list]" ascii //weight: 2
        $x_2_15 = "[Far Manager passwords]" ascii //weight: 2
        $x_2_16 = "[The Bat passwords]" ascii //weight: 2
        $x_2_17 = "[Total Commander ftp passwords]" ascii //weight: 2
        $x_2_18 = "[Protected Storage data already sended]" ascii //weight: 2
        $x_2_19 = "<CENTER><B>Keys entered on SRK Keypad</B></CENTER><BR><CENTER>" ascii //weight: 2
        $x_2_20 = "[Warning: the last formdata have one valid tan]" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

