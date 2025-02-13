rule Backdoor_Win32_Poftsyun_A_2147679394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poftsyun.A"
        threat_id = "2147679394"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poftsyun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nd not support!" ascii //weight: 1
        $x_1_2 = "ot create file on client!" ascii //weight: 1
        $x_1_3 = "Serverfile is smaller than Clientfile!" ascii //weight: 1
        $x_1_4 = "ClientFile is smaller than ServerFile!" ascii //weight: 1
        $x_1_5 = "ot open file on client with append mode!" ascii //weight: 1
        $x_1_6 = "is not exist or stopped!" ascii //weight: 1
        $x_1_7 = "__utmz%3D173272373" ascii //weight: 1
        $x_1_8 = "translate_logo.gif" ascii //weight: 1
        $x_1_9 = "Proxy Type:%s" ascii //weight: 1
        $x_1_10 = "/dc/launch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_Win32_Poftsyun_B_2147679396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Poftsyun.B"
        threat_id = "2147679396"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Poftsyun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/uc_server/data/forum.asp" ascii //weight: 1
        $x_1_2 = "/blassic/acount/image/addr_member.asp" ascii //weight: 1
        $x_1_3 = "RL download success!" ascii //weight: 1
        $x_1_4 = "te file error!" ascii //weight: 1
        $x_1_5 = "\\\\.\\pipe\\ssnp" ascii //weight: 1
        $x_1_6 = "ot bigger than Clientfile!" ascii //weight: 1
        $x_1_7 = "ot bigger than Serverfile" ascii //weight: 1
        $x_1_8 = "toobu.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

