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

rule Trojan_Win32_Blihan_AB_2147952700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blihan.AB!MTB"
        threat_id = "2147952700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blihan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 94 24 1c 02 00 00 83 c9 ff 8b fa 33 c0 f2 ae f7 d1 49 51 52 8b 54 24 0c 6a 01 8d}  //weight: 1, accuracy: High
        $x_1_2 = {81 ec 14 02 00 00 8d ?? ?? ?? c7 44 24 00 00 00 00 00 50 68 3f 00 0f 00 6a 00 68 a4 61 40 00 68 01 00 00 80 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

