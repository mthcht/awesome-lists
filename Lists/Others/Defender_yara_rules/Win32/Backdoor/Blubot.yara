rule Backdoor_Win32_Blubot_A_2147705623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Blubot.A"
        threat_id = "2147705623"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Blubot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DoSAttack" ascii //weight: 1
        $x_1_2 = "MCBOT" wide //weight: 1
        $x_1_3 = "HTTPPacker" ascii //weight: 1
        $x_1_4 = "Blue_Botnet" ascii //weight: 1
        $x_1_5 = "\\sysfile.exe" wide //weight: 1
        $x_1_6 = "botlogger.php" wide //weight: 1
        $x_1_7 = "prv_attack" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

