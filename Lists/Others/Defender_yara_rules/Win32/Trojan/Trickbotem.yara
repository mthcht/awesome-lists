rule Trojan_Win32_Trickbotem_A_2147766702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trickbotem.A!mod"
        threat_id = "2147766702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trickbotem"
        severity = "Critical"
        info = "mod: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Grabbed %s from Inbox" ascii //weight: 1
        $x_1_2 = "Grabbed %s from Contacts" ascii //weight: 1
        $x_1_3 = "Error hiding Outlook from the taskbar" ascii //weight: 1
        $x_1_4 = "Hide Outlook from system tray" ascii //weight: 1
        $x_1_5 = "StartOutlook(): before hide" ascii //weight: 1
        $x_1_6 = "c:\\temp\\mail.log" ascii //weight: 1
        $x_1_7 = "StartOutlook(): ShellExecuteW()  %S %S" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

