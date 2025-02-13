rule Trojan_Win32_Bokbot_GG_2147745020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bokbot.GG!MTB"
        threat_id = "2147745020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bokbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 50 8b 45 ?? c7 [0-6] 50 ff 15 [0-15] 50 ff 15 [0-4] 66 8b ?? 81 [0-5] ff 15 [0-4] 8d [0-2] 88 [0-2] ff 15 [0-4] 8d [0-2] ff 15 [0-4] 8b [0-2] 8b [0-2] 8b ?? c1 [0-2] 8b ?? 33 ?? 33 ?? 3b [0-7] 8b ?? 85 [0-3] 66}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d0 8d 4d [0-7] 50 ff 15 [0-4] 66 8b ?? 81 [0-5] ff 15 [0-4] 8d [0-2] 88 [0-2] ff 15 [0-4] 8d [0-2] ff 15 [0-4] 8b [0-2] 8b [0-2] 8b [0-2] c1 [0-2] 8b ?? 33 ?? 33 ?? 3b [0-7] 8b ?? 85 [0-3] 66}  //weight: 1, accuracy: Low
        $x_1_3 = {25 ff 00 00 00 8b ?? 33 ?? 83 [0-2] 33 ?? ff 15 [0-4] 8b ?? 8b [0-2] 88 [0-2] 8b [0-2] 8b [0-2] 03 [0-7] 8b ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

