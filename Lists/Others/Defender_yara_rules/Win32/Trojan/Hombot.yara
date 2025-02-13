rule Trojan_Win32_Hombot_A_2147724236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hombot.A!dha"
        threat_id = "2147724236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hombot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "username=77da9155ac3f78787fe60cfdc784845d&password=c81088058303ee1599203127e53ee0fc&button=Login" ascii //weight: 5
        $x_5_2 = "C:\\Users\\xman_1365_x\\Desktop" ascii //weight: 5
        $x_1_3 = "&ttype=102&state=301&IDOP=" ascii //weight: 1
        $x_1_4 = "&ttype=102&state=201" ascii //weight: 1
        $x_1_5 = "\\deskcapture.bmp" ascii //weight: 1
        $x_1_6 = "\\deskcapture.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

