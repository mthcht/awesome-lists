rule Trojan_Win32_Diltacs_A_2147647883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Diltacs.A"
        threat_id = "2147647883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Diltacs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hits?act=4&aid=" ascii //weight: 1
        $x_1_2 = "username=" ascii //weight: 1
        $x_1_3 = "password=" ascii //weight: 1
        $x_1_4 = "adslname=" ascii //weight: 1
        $x_1_5 = "adslauto=" ascii //weight: 1
        $x_1_6 = "MissWho_OK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

