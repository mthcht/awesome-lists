rule Trojan_Win32_ZionSiphon_RH_2147969142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZionSiphon.RH!MTB"
        threat_id = "2147969142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZionSiphon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4e a5 01 00 00 20}  //weight: 2, accuracy: Low
        $x_2_2 = "Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_1_3 = "SystemHealthCheck" wide //weight: 1
        $x_1_4 = "Target not matched" wide //weight: 1
        $x_1_5 = "Operation restricted to IL ranges" wide //weight: 1
        $x_1_6 = "svchost.exe" wide //weight: 1
        $x_1_7 = "powershell.exe" wide //weight: 1
        $x_1_8 = "Israel" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

