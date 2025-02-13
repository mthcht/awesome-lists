rule Trojan_Win32_WellMess_A_2147760031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WellMess.A!MTB"
        threat_id = "2147760031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WellMess"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bot/botlib.AES_Encrypt" ascii //weight: 1
        $x_1_2 = "bot/botlib.convertFromString" ascii //weight: 1
        $x_1_3 = "master secret" ascii //weight: 1
        $x_1_4 = "key expansion" ascii //weight: 1
        $x_1_5 = "client finished" ascii //weight: 1
        $x_1_6 = "server finished" ascii //weight: 1
        $x_1_7 = "CLNTSRVR" ascii //weight: 1
        $x_3_8 = "Go build ID: \"27c6bd7063f3668f7f223ecbb56d5a604baa1fb1\"" ascii //weight: 3
        $x_3_9 = "Go build ID: \"92b19bbcbb2387e08500c6db1a3bfb8c9ba4a12" ascii //weight: 3
        $x_3_10 = "Go build ID: \"bb423eb5fe835ec3449adefdb3b66421a0b6f7be" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WellMess_B_2147760032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WellMess.B!MTB"
        threat_id = "2147760032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WellMess"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "botlib.z32decode" ascii //weight: 1
        $x_1_2 = "botlib.z32decodeString" ascii //weight: 1
        $x_1_3 = "botlib.Send.func1" ascii //weight: 1
        $x_1_4 = "botlib.SendD.func1" ascii //weight: 1
        $x_1_5 = "botlib.init" ascii //weight: 1
        $x_1_6 = "fakeLocker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

