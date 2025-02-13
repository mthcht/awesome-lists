rule Trojan_Win32_Paynebot_SBR_2147764528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Paynebot.SBR!MSR"
        threat_id = "2147764528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Paynebot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "66.171.248.178" ascii //weight: 1
        $x_1_2 = "Dropped by MAATrigger-Payload" ascii //weight: 1
        $x_1_3 = "Host: bot.whatismyipaddress.com" ascii //weight: 1
        $x_1_4 = "locked down user with limited OS access" ascii //weight: 1
        $x_1_5 = "Lock_policy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

