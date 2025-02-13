rule Trojan_Win32_DarkMoon_A_2147793759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkMoon.A!MTB"
        threat_id = "2147793759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ExuiKrnln.dll" ascii //weight: 1
        $x_1_2 = "ExuiKrnln.ini" ascii //weight: 1
        $x_1_3 = "http://note.youdao.com/yws/api/personal/file/7B292D4DB61D4B3899993B2340E12A89" ascii //weight: 1
        $x_1_4 = "BlackMoon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

