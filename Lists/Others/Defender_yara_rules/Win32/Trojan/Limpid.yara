rule Trojan_Win32_Limpid_BAA_2147947008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Limpid.BAA!MTB"
        threat_id = "2147947008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Limpid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".pdf" ascii //weight: 1
        $x_10_2 = " /c echo>>@" ascii //weight: 10
        $x_1_3 = ".cmd set mail-out" ascii //weight: 1
        $x_1_4 = ".cmd set smtp=mail.vniir.nl" ascii //weight: 1
        $x_1_5 = "\\driver.exe x -r -ep2 -p" ascii //weight: 1
        $x_1_6 = ".cmd schtasks /create /tn" ascii //weight: 1
        $x_1_7 = "cmd.exe exec hide @" ascii //weight: 1
        $x_1_8 = "task.bat" ascii //weight: 1
        $x_1_9 = "/sc onlogon /rl highest /f" ascii //weight: 1
        $x_1_10 = "AutoUpdate Driver" ascii //weight: 1
        $x_1_11 = "bat2.bat" ascii //weight: 1
        $x_1_12 = "/sc hourly /st 00:00 /ru SYSTEM /f" ascii //weight: 1
        $x_1_13 = "cmd bat.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

