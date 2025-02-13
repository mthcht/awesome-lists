rule Trojan_Win32_MpTestSMSThreat_2147727342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTestSMSThreat"
        threat_id = "2147727342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTestSMSThreat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MS AVAS MpTestSMSThreat" ascii //weight: 1
        $x_1_2 = "Internal test only! Do not distribute outside your team!" ascii //weight: 1
        $x_1_3 = "SMS detection to be reported as a threat" ascii //weight: 1
        $x_1_4 = "fc586351-bdf9-4fab-bb28-7d363777a42c" ascii //weight: 1
        $x_1_5 = "feb8be96-4417-4bc7-8bd3-2cd2fdfac66e" ascii //weight: 1
        $x_1_6 = "4a7dac5e-83f6-496c-b5e7-68008acfbf51" ascii //weight: 1
        $x_1_7 = "b6fbc58a-dc59-4755-9083-fa3e696f1acc" ascii //weight: 1
        $x_1_8 = "dc5460db-1b91-47a0-95d7-c3e66fd65178" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

