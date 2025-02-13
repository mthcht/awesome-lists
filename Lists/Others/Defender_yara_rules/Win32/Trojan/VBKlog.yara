rule Trojan_Win32_VBKlog_EM_2147917923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBKlog.EM!MTB"
        threat_id = "2147917923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBKlog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiVirusDisableNotify" ascii //weight: 1
        $x_1_2 = "FirewallDisableNotify" ascii //weight: 1
        $x_1_3 = "UpdatesDisableNotify" ascii //weight: 1
        $x_1_4 = "netsh firewall set opmode disable" ascii //weight: 1
        $x_1_5 = "CLIPBOARD CHANGED" ascii //weight: 1
        $x_1_6 = "FuckYourSelf" ascii //weight: 1
        $x_1_7 = "keylogger - FTP - bedune error - Revision1\\winlogon.vbp" ascii //weight: 1
        $x_1_8 = "proje cod injector_new method\\Extracter\\Standard.vbp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

