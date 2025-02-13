rule Backdoor_Win32_RedLeaves_A_2147723451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/RedLeaves.A!dha"
        threat_id = "2147723451"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLeaves"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "__serial" ascii //weight: 1
        $x_1_2 = "__msgid" ascii //weight: 1
        $x_1_3 = "__data" ascii //weight: 1
        $x_1_4 = "OnlineTime=" wide //weight: 1
        $x_1_5 = "cmd.exe /c start" wide //weight: 1
        $x_1_6 = "clientpath=" ascii //weight: 1
        $x_1_7 = "serverpath=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

