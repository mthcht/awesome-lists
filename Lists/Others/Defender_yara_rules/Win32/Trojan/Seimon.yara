rule Trojan_Win32_Seimon_A_2147600393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Seimon.gen!A"
        threat_id = "2147600393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Seimon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".php?ovt=%CLIENTID" ascii //weight: 1
        $x_1_2 = "&ipaddr=%IP" ascii //weight: 1
        $x_3_3 = "PacketSnifferClass1" ascii //weight: 3
        $x_1_4 = "?ec=%OVERTUREID" ascii //weight: 1
        $x_1_5 = "&pt=3&max=5&query=" ascii //weight: 1
        $x_1_6 = "href=\"%CLICKURL\" target=\"_blank\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

