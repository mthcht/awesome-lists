rule PWS_Win32_Keylogger_C_2147605536_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Keylogger.C"
        threat_id = "2147605536"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKCU\\software\\microsoft\\windows\\currentversion\\policies\\system\\disableregistrytools" wide //weight: 1
        $x_1_2 = "HKCU\\software\\microsoft\\windows\\currentversion\\policies\\system\\DisableTaskMgr" wide //weight: 1
        $x_1_3 = "Program Files\\Yahoo!\\Messenger\\Profiles\\" wide //weight: 1
        $x_1_4 = "HKCU\\software\\Yahoo\\Pager\\Save Password" wide //weight: 1
        $x_1_5 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_6 = "InternetExplorerPassword[" wide //weight: 1
        $x_1_7 = "FtpSetCurrentDirectoryA" ascii //weight: 1
        $x_1_8 = "system32\\Microsoft\\" wide //weight: 1
        $x_1_9 = "DialUpPassword[" wide //weight: 1
        $x_1_10 = "wscript.shell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Keylogger_D_2147611325_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Keylogger.D"
        threat_id = "2147611325"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 e8 89 44 24 04 c7 04 24 ?? 00 00 00 e8 ?? ?? 00 00 8b 45 e8 89 04 24 e8 ?? ?? 00 00 eb ?? 8b 45 e8 89 44 24 04 c7 04 24 ?? 00 00 00 e8 ?? ?? 00 00 8b 45 e8 89 04 24 e8 ?? ?? 00 00 eb}  //weight: 10, accuracy: Low
        $x_2_2 = "peroxyde.paypal@gmail.com" ascii //weight: 2
        $x_2_3 = "helo me.somepalace.com" ascii //weight: 2
        $x_2_4 = "Started logging:" ascii //weight: 2
        $x_1_5 = "sound.wav" ascii //weight: 1
        $x_1_6 = "gmail-smtp-in.l.google.com" ascii //weight: 1
        $x_1_7 = "RCPT TO:<" ascii //weight: 1
        $x_1_8 = "[CAPS LOCK]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

