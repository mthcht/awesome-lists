rule Trojan_Win32_Blihan_MA_2147840854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blihan.MA!MTB"
        threat_id = "2147840854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blihan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 14 28 30 14 31 40 41 3d 80 00 00 00 7c ?? 33 c0 3b cf 7c}  //weight: 5, accuracy: Low
        $x_5_2 = {56 8b 74 24 0c 57 8b 7c 24 0c 2b f7 8d 0c 17 42 8a 04 0e 4a 88 01 49 85 d2 77 f5}  //weight: 5, accuracy: High
        $x_1_3 = "pomdfghrt" ascii //weight: 1
        $x_1_4 = "WindowsHookExON" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

