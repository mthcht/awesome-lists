rule Trojan_Win32_SystemDiscovery_B_2147768428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemDiscovery.B!msinfo"
        threat_id = "2147768428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemDiscovery"
        severity = "Critical"
        info = "msinfo: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 6e 00 66 00 6f 00 [0-16] 2f 00 6e 00 66 00 6f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SystemDiscovery_B_2147768429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemDiscovery.B!sysinfo"
        threat_id = "2147768429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemDiscovery"
        severity = "Critical"
        info = "sysinfo: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "systeminfo" wide //weight: 1
        $n_10_2 = "> c:\\programdata\\microsoft\\windows defender\\support\\" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

