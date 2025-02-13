rule TrojanDropper_Win32_Redroshex_A_2147640375_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Redroshex.gen!A"
        threat_id = "2147640375"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Redroshex"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {51 53 56 57 68 ?? ?? ?? ?? 6a 66 6a 00 ff 15 ?? ?? ?? ?? 8b f0 56 6a 00 ff 15 ?? ?? ?? ?? 56 6a 00 8b f8 ff 15 ?? ?? ?? ?? 6a 00 68 80 00 00 00 6a 02 6a 00 6a 01 68 00 00 00 c0 68 ?? ?? ?? ?? 8b d8 ff 15 ?? ?? ?? ?? 8b f0 8d 44 24 0c 6a 00 50 57 53 56 ff 15 ?? ?? ?? ?? 85 c0 74 07 56 ff 15 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 5f 5e 5b 59 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

