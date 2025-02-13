rule Trojan_Win32_Stolpen_D_2147731043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stolpen.D"
        threat_id = "2147731043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stolpen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net user %s Security1215! /add" ascii //weight: 1
        $x_1_2 = "net user %s waldo1215! /add" ascii //weight: 1
        $x_2_3 = "/EXPIRES:NEVER /Active:YES&net localgroup users %s /delete&net localgroup Administrators %s /add" ascii //weight: 2
        $x_2_4 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii //weight: 2
        $x_2_5 = "fDenyTSConnections" ascii //weight: 2
        $x_2_6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

