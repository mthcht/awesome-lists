rule Trojan_Win32_WebHijack_A_2147641882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebHijack.A!sys"
        threat_id = "2147641882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebHijack"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 7f 0c 81 ff 80 0c 00 80 74 ?? 81 ff ac 0c 00 80 74}  //weight: 3, accuracy: Low
        $x_1_2 = "WebHijack" ascii //weight: 1
        $x_1_3 = "\\websafe" wide //weight: 1
        $x_1_4 = "\\Control\\Webhj" wide //weight: 1
        $x_1_5 = "Search" wide //weight: 1
        $x_1_6 = "\\Device\\Tcp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WebHijack_A_2147641883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebHijack.A!dll"
        threat_id = "2147641883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebHijack"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b6 02 c1 e0 06 25 c0 00 00 00 03 45 ?? 89 45 ?? 8b 4d ?? 03 4d ?? 8a 55 ?? 88 11}  //weight: 3, accuracy: Low
        $x_3_2 = {8a d1 c0 ea 02 02 c0 80 e2 0c 02 c2 c0 e9 06 02 c1 88 04 3e 83 c6 01 3b f5 72 d2}  //weight: 3, accuracy: High
        $x_1_3 = "WebHijack" ascii //weight: 1
        $x_1_4 = "\\websafe.sys" ascii //weight: 1
        $x_1_5 = "\\SafeBoot\\Minimal\\%s.sys" ascii //weight: 1
        $x_1_6 = "IsDriverRunning" ascii //weight: 1
        $x_1_7 = "LoadConfig" ascii //weight: 1
        $x_1_8 = "cutil_driver_OpenDevice" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

