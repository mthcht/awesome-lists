rule Trojan_Win32_NefilimGo_A_2147767702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NefilimGo.A!MTB"
        threat_id = "2147767702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NefilimGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "main.SaveNote.func" ascii //weight: 1
        $x_1_2 = "main.FileSearch.func" ascii //weight: 1
        $x_1_3 = "main.getdrives" ascii //weight: 1
        $x_1_4 = "main.UnixFile" ascii //weight: 1
        $x_1_5 = "main.GenerateRandomBytes" ascii //weight: 1
        $x_1_6 = "path/filepath.SkipDir" ascii //weight: 1
        $x_1_7 = {66 0f 1f 84 00 00 00 00 00 81 ff 80 00 00 00 0f 8d c3 01 00 00 48 ff c0 48 89 ?? ?? 60 48 8d ?? ?? 44 48 89 0c 24 48 63 cf 48 89 ?? ?? 58 48 89 ?? ?? 08 e8 ?? ?? ?? ?? 48 8b ?? ?? 10 48 8b ?? ?? 18 48 c7 ?? ?? 00 00 00 00 48 89 ?? ?? 08 48 89 ?? ?? 10 48 8d 05 84 21 03 00 48 89 ?? ?? 18 48 c7 ?? ?? 20 02 00 00 00 e8 ?? ?? ?? ?? 48 8b ?? ?? 28 48 8b ?? ?? 30 48 89 ?? ?? 48 89 ?? ?? 08 48 c7 ?? ?? 10 00 00 00 00 c7 ?? ?? 18 00 00 00 00 e8 ?? ?? ?? ?? 48 8b ?? ?? 20 48 83 ?? ?? 28 00 74 17 48 8b ?? ?? 70 48 8b ?? ?? 68 48 8b 94 24 90 00 00 00 e9 10 ff ff ff 48 89 ?? ?? 78 48 c7 ?? ?? 00 00 00 00 48 8b ?? ?? 58 48 89 ?? ?? 08 e8 ?? ?? ?? ?? 48 8b ?? ?? 70 48 8d 48 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

