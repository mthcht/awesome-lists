rule Trojan_Win32_Proxage_A_2147707873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Proxage.A!dha"
        threat_id = "2147707873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Proxage"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MirageFox" ascii //weight: 1
        $x_1_2 = ".mechanicnote.com" ascii //weight: 1
        $x_1_3 = "/search?gid=%s" ascii //weight: 1
        $x_1_4 = "/c del %s > nul" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

