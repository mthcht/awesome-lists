rule Trojan_Win32_Fushield_A_2147711794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fushield.A!bit"
        threat_id = "2147711794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fushield"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {88 54 35 c8 46 3b f7 7c 0b 00 e8 ?? ?? ?? ?? 99 f7 fb 80 c2 61}  //weight: 4, accuracy: Low
        $x_4_2 = ".temp.fortest" ascii //weight: 4
        $x_3_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 3
        $x_1_4 = "EnableLUA" ascii //weight: 1
        $x_1_5 = "PromptOnSecureDesktop" ascii //weight: 1
        $x_1_6 = "UACDisableNotify" ascii //weight: 1
        $x_10_7 = "FuckShieldRefreshMutex" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

