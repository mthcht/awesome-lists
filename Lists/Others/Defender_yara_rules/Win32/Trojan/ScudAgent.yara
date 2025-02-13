rule Trojan_Win32_ScudAgent_A_2147650304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ScudAgent.gen!A"
        threat_id = "2147650304"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ScudAgent"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "{7AA7833B-1231-4714-ASDA-C9D28D4B4DF9}" ascii //weight: 2
        $x_3_2 = "http://scud.pipis.net/" ascii //weight: 3
        $x_3_3 = "&ScudAxSendKey=" ascii //weight: 3
        $x_2_4 = "KeyAddressPopUp" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

