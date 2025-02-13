rule Trojan_Win32_HydraCrypt_ED_2147835922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HydraCrypt.ED!MTB"
        threat_id = "2147835922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HydraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A_READ_ME.TXT" wide //weight: 1
        $x_1_2 = "SELECT * FROM Win32_ShadowCopy" wide //weight: 1
        $x_1_3 = "cmd.exe /c C:\\Windows\\System32\\wbem\\WMIC.exe shadowcopy" wide //weight: 1
        $x_1_4 = "WSearchDNS" wide //weight: 1
        $x_1_5 = "runrun" wide //weight: 1
        $x_1_6 = "KFLJSDHijfq3n2iufq3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_HydraCrypt_BAH_2147845327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HydraCrypt.BAH!MTB"
        threat_id = "2147845327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HydraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {88 0c 10 0f b6 55 ff 8b 45 f8 0f b6 0c 10 0f b6 55 fe 8b 45 f8 0f b6 14 10 03 ca 81 e1 ff 00 00 00 8b 45 f8 0f b6 0c 08 8b 55 08 03 55 f4 0f b6 02 33 c1 8b 4d 08 03 4d f4 88 01 e9}  //weight: 3, accuracy: High
        $x_2_2 = {6a 04 68 00 30 00 00 6a 75 6a 00 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

