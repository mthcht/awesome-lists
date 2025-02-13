rule Trojan_Win32_Barsebey_A_2147682925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barsebey.A"
        threat_id = "2147682925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barsebey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "204"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {0f b6 fb 8b 55 fc 0f b6 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 45 fc 0f b6 44 38 ff}  //weight: 100, accuracy: High
        $x_102_2 = "23C58D186E416D4A8D518A3A73E1C7A83F6A6CF8679DD50DCE9AAC0EC4" ascii //weight: 102
        $x_1_3 = "mywebsearch.com/jsp/cfg_redir2" ascii //weight: 1
        $x_1_4 = "$$336699.bat" ascii //weight: 1
        $x_1_5 = "cnsyshost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_102_*) and 1 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

