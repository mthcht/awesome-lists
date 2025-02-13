rule Trojan_Win32_Daiboo_A_2147582088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daiboo.A"
        threat_id = "2147582088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daiboo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_2 = "Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_3 = "Explorer\\Advanced\\Folder\\Hidden" ascii //weight: 1
        $x_1_4 = "eleteme.bat" ascii //weight: 1
        $x_1_5 = "if exist \"" ascii //weight: 1
        $x_1_6 = "goto try" ascii //weight: 1
        $x_1_7 = "Trojan" ascii //weight: 1
        $x_1_8 = "Firewall" ascii //weight: 1
        $x_1_9 = "Kaspersky" ascii //weight: 1
        $x_1_10 = "AntiVirus" ascii //weight: 1
        $x_1_11 = "ZoneAlarm" ascii //weight: 1
        $x_1_12 = "autoruns.exe" ascii //weight: 1
        $x_1_13 = "JumpHookOn" ascii //weight: 1
        $x_1_14 = "JumpHookOff" ascii //weight: 1
        $x_1_15 = "Insert.dll" ascii //weight: 1
        $n_100_16 = "SpecialSpyHandler.dll" ascii //weight: -100
        $n_100_17 = "detail.webrootcloudav.com/" ascii //weight: -100
        $n_100_18 = "Webroot SecureAnywhere" wide //weight: -100
        $n_100_19 = "Webroot Secure Anywhere" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (12 of ($x*))
}

