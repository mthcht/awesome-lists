rule Backdoor_Win32_Stradatu_2147681809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Stradatu"
        threat_id = "2147681809"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Stradatu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LFN=%s&LFL=%ld&RFN=%s" ascii //weight: 1
        $x_1_2 = "friend is Unavailable!" ascii //weight: 1
        $x_1_3 = ":\\pjts2008\\SunTalk\\Release\\STalk_S.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Stradatu_2147681809_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Stradatu"
        threat_id = "2147681809"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Stradatu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Reqfile not exist!" ascii //weight: 1
        $x_1_2 = "d file failure!" ascii //weight: 1
        $x_1_3 = "Y21kLmV4ZQ==" ascii //weight: 1
        $x_1_4 = "RUheYodtaXyudTy4a3I5NjVxNkZxPR!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Stradatu_2147681809_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Stradatu"
        threat_id = "2147681809"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Stradatu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1.3.6.1.5.5.7.3.2" ascii //weight: 1
        $x_1_2 = "4.1.311.10.3.3" ascii //weight: 1
        $x_2_3 = "REVERSESHELL" ascii //weight: 2
        $x_2_4 = "UNKNOW CLIENT TYPE" ascii //weight: 2
        $x_2_5 = "UNKNOW HOST TYPE" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Stradatu_2147681809_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Stradatu"
        threat_id = "2147681809"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Stradatu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fxjmpsvalzydg" ascii //weight: 1
        $x_1_2 = "*&userid=****&other=" ascii //weight: 1
        $x_1_3 = "pt_LXC_3" ascii //weight: 1
        $x_1_4 = "te Command Socket Build OK!" ascii //weight: 1
        $x_1_5 = "at \"IP PORT\"!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Stradatu_2147681809_4
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Stradatu"
        threat_id = "2147681809"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Stradatu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "n Path is null!" ascii //weight: 1
        $x_1_2 = "<TITLE>Display Info for this SITE!</TITLE>" ascii //weight: 1
        $x_1_3 = "content=quit" ascii //weight: 1
        $x_1_4 = "%a, %d %b %Y %H:%M:%S GMT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Stradatu_2147681809_5
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Stradatu"
        threat_id = "2147681809"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Stradatu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "r quit![all sleep nnn time]" ascii //weight: 1
        $x_1_2 = "<NULL> Password<NULL> Domain<NULL>" ascii //weight: 1
        $x_1_3 = "*** JMS-HT ***" ascii //weight: 1
        $x_1_4 = "l in another shell!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Stradatu_2147681809_6
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Stradatu"
        threat_id = "2147681809"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Stradatu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t localgroup administrators abc /add" ascii //weight: 1
        $x_1_2 = "t user abc abc /add" ascii //weight: 1
        $x_1_3 = "ReqPath is null!" ascii //weight: 1
        $x_1_4 = "ARE YOU SURE CLOSE CLIENT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Stradatu_2147681809_7
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Stradatu"
        threat_id = "2147681809"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Stradatu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "for quit![all sleep nnn time]" ascii //weight: 1
        $x_1_2 = "************ New client coming ! **************" ascii //weight: 1
        $x_1_3 = "Bad Client, please remove it!" ascii //weight: 1
        $x_1_4 = "%s goes to bed! Wish him a good sleep!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

