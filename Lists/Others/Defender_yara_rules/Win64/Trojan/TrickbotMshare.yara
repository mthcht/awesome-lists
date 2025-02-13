rule Trojan_Win64_TrickbotMshare_A_2147766734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrickbotMshare.A!MTB"
        threat_id = "2147766734"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrickbotMshare"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7c8DhxWXjErT7C/z7ce" ascii //weight: 1
        $x_1_2 = "4Pj+/D9oJP4ZJDyoG2j+/D9oJc7qG2j1JD4MuLYLIE+oVg5" ascii //weight: 1
        $x_1_3 = "PDPqIPj+/D9oJGjcIG4Lswjo" ascii //weight: 1
        $x_1_4 = "IgYMmw4d/CWzmw9a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

