rule Trojan_Win32_Cionrox_A_2147627226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cionrox.A"
        threat_id = "2147627226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cionrox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo \"AutoConfigURL\"=\"http://%ok%/proxy.pac\" >> iecfg1.reg" ascii //weight: 1
        $x_1_2 = "echo user_pref(\"network.proxy.autoconfig_url\", \"http://%ok%/proxy.pac\");" ascii //weight: 1
        $x_1_3 = "DO echo grant {  permission java.security.AllPermission" ascii //weight: 1
        $x_1_4 = "reg add \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cionrox_B_2147633663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cionrox.B"
        threat_id = "2147633663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cionrox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 81 00 00 00 e8 ?? ?? ?? ?? 8b d8 85 db 7e 10 8d 95 ?? ?? ff ff 8b cb 8b 45 ?? 8b 30 ff 56 10 85 db 7f bb}  //weight: 1, accuracy: Low
        $x_1_2 = {75 71 8d 55 e8 b8 1a 00 00 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = "//infec.php" ascii //weight: 1
        $x_1_4 = "user_pref(\"network.proxy.autoconfig_url\", \"http://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

