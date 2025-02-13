rule Trojan_Win32_Multiverze_RF_2147787197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Multiverze.RF!MTB"
        threat_id = "2147787197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Multiverze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "www.gpmce.net" ascii //weight: 5
        $x_5_2 = "www.booble.com" ascii //weight: 5
        $x_1_3 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_4 = "regwrite" ascii //weight: 1
        $x_1_5 = "startup" ascii //weight: 1
        $x_1_6 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

