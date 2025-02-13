rule TrojanDropper_Win32_Rochap_A_2147627740_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rochap.gen!A"
        threat_id = "2147627740"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rochap"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 0f 32 d8 80 f3 0a 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 3a ff 80 e2 f0 02 d3 88 54 38 ff 46 8b 45 f4 e8 ?? ?? ?? ?? 3b f0 7e 05}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 60 ea 00 00 e8 ?? ?? ?? ?? eb 0c 53}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 02 68 80 00 00 00 6a 00 8b 45 f8 e8 ?? ?? ?? ?? b9 02 00 00 00 ba 00 00 00 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

