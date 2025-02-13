rule Trojan_Win32_Jinto_A_2147645524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jinto.A"
        threat_id = "2147645524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jinto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 c7 06 e5 fa ae 4f e8 ?? ?? ?? ?? 0f af 06 8b 4d fc 0f af 4d f8 69 c9 ca 3d e0 cf 33 c1 6a 04 56 89 06 e8 ?? ?? ?? ?? 8b 4d fc 69 c9 20 1f d9 50}  //weight: 1, accuracy: Low
        $x_1_2 = {56 8b 54 24 08 8b 74 24 0c fa 0f 20 c1 8b c1 81 e1 ff ff fe ff 0f 22 c1 f0 87 32 0f 22 c0 fb 8b c6 5e c2 08 00}  //weight: 1, accuracy: High
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\%s" ascii //weight: 1
        $x_1_4 = "SeLoadDriverPrivilege" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Jinto_A_2147645526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jinto.A!dll"
        threat_id = "2147645526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jinto"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {67 65 74 63 6f 72 65 63 6f 6e 66 69 67 00 00 00 67 65 74 70 6c 75 67 69 6e 63 6f 6e 66 69 67}  //weight: 10, accuracy: High
        $x_10_2 = "%s_Start_%c_up" ascii //weight: 10
        $x_10_3 = "SYSTEM\\CurrentControlSet\\Services\\%s" ascii //weight: 10
        $x_1_4 = "act=update&bot_id=%s&bid=%s&os=%d&version=%d&sp=%d&socks=%d" ascii //weight: 1
        $x_1_5 = "act=getplugin&bot_id=%s&plugin_name=%s" ascii //weight: 1
        $x_1_6 = "act=%s&bot_id=%s&plugin_name=%s" ascii //weight: 1
        $x_1_7 = "act=out&bot_id=%s&data_type=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

