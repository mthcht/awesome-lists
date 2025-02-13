rule Trojan_Win32_SilverSword_A_2147696094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SilverSword.A!dha"
        threat_id = "2147696094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SilverSword"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1000"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\sysconf.dll" ascii //weight: 1
        $x_1_2 = "StartKeylog" ascii //weight: 1
        $x_1_3 = "<Delete>" ascii //weight: 1
        $x_1_4 = "mskey.dll" ascii //weight: 1
        $x_1_5 = "[Keys]" ascii //weight: 1
        $x_1_6 = "cmd /c systeminfo >> \"%s\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

