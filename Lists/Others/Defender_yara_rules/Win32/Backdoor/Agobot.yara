rule Backdoor_Win32_Agobot_A_2147594988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Agobot.A"
        threat_id = "2147594988"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Agobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#enc#.tmp" ascii //weight: 1
        $x_1_2 = "#enc#%s%s%08X.tmp" ascii //weight: 1
        $x_1_3 = "SendTCP(): sid=%d" ascii //weight: 1
        $x_1_4 = "SendTCP(): Sent %d bytes" ascii //weight: 1
        $x_1_5 = "SendTCP(): Got %d/%d bytes" ascii //weight: 1
        $x_1_6 = "#enc#MiniDumpWriteDump" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

