rule Ransom_Win64_Blocker_AJ_2147982563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Blocker.AJ!MTB"
        threat_id = "2147982563"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 45 af 48 8d 05 ?? ?? ?? ?? 48 89 45 b7 4c 89 6d bf 4c 89 6d c7 48 8d 4d af}  //weight: 10, accuracy: Low
        $x_8_2 = {4d 8b c4 4d 2b c6 4d 03 c0 4b 8d 04 26 48 8d 0d ?? ?? ?? ?? 48 8d 14 41 49 8d 0c 1f}  //weight: 8, accuracy: Low
        $x_6_3 = "yngsmss.exe" ascii //weight: 6
        $x_2_4 = "/Delete /TN YngDriverBootHeal /F" ascii //weight: 2
        $x_4_5 = "ip-server.txt" ascii //weight: 4
        $x_3_6 = "redirect.txt" ascii //weight: 3
        $x_7_7 = "device_id.txt" ascii //weight: 7
        $x_5_8 = "Global\\WpnPlatformHost.Edge" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

