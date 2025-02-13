rule Trojan_Win32_AutoitZbot_RA_2147847382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitZbot.RA!MTB"
        threat_id = "2147847382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitZbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net user sysadm h3l_pdesk /expires:never" ascii //weight: 1
        $x_1_2 = "net localgroup \"\"remote desktop users\"\" DHCP /add" ascii //weight: 1
        $x_1_3 = "winlogon\\specialaccounts\\userlist\" , \"sysadm\"" ascii //weight: 1
        $x_1_4 = "firewall set opmode disable\" , \"\" , @SW_HIDE )" ascii //weight: 1
        $x_1_5 = "RUN ( @TEMPDIR & \"\\upgrade.exe\" , \"\" , @SW_HIDE )" ascii //weight: 1
        $x_1_6 = "control\\terminal server\"\" /v fdenytsconnections /t reg_dword /d 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

