rule Backdoor_Win32_Codbot_BY_2147583214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Codbot.BY"
        threat_id = "2147583214"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Codbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ftpd.status" ascii //weight: 1
        $x_1_2 = ".scan.infected" ascii //weight: 1
        $x_1_3 = ".bot.sysinfo" ascii //weight: 1
        $x_1_4 = ".bot.ip" ascii //weight: 1
        $x_1_5 = "QUIT :god hates us all" ascii //weight: 1
        $x_1_6 = "xPerFHmoNx" ascii //weight: 1
        $x_1_7 = "mindleak.com" ascii //weight: 1
        $x_1_8 = "0x80.martiansong.com" ascii //weight: 1
        $x_1_9 = "0x80.my1x1.com" ascii //weight: 1
        $x_1_10 = "0x80.online-software.org" ascii //weight: 1
        $x_1_11 = "\\C$\\123456111111111111111.doc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

