rule TrojanProxy_Win32_Chumpoke_A_2147597510_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Chumpoke.gen!A"
        threat_id = "2147597510"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Chumpoke"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 23 8d 95 74 ff ff ff b9 20 00 00 00 8b 45 fc e8 ?? ?? ff ff 83 f8 0a 0f 82 ?? 01 00 00 8b 85 74 ff ff ff 80 78 09 5d 75 2f 8d 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

