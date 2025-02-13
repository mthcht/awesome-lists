rule Trojan_Win32_DriverUpdater_A_2147730864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DriverUpdater.A"
        threat_id = "2147730864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DriverUpdater"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\JobRelease\\win\\Release\\stubs\\x86" ascii //weight: 1
        $x_1_2 = "[AppDataFolder]System Updates\\Windows Driver System Update" wide //weight: 1
        $x_1_3 = "\\FAKE_DIR\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

