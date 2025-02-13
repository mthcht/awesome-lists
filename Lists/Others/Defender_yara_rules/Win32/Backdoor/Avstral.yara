rule Backdoor_Win32_Avstral_A_2147624808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Avstral.gen!A"
        threat_id = "2147624808"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Avstral"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 ff 00 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 6a 20 6a 04 6a 00 6a 01 68 00 00 00 c0 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 02 6a 00 6a 00 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 75 08 e8}  //weight: 10, accuracy: Low
        $x_10_2 = "\\Wini.ini" ascii //weight: 10
        $x_10_3 = "InstallHook" ascii //weight: 10
        $x_1_4 = "HELO mail.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

