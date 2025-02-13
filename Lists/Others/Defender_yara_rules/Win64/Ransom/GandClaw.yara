rule Ransom_Win64_GandClaw_A_2147729752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GandClaw.A"
        threat_id = "2147729752"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GandClaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 bd 99 a9 aa aa ed 44 8b c3 48 8b cf 89 44 24 ?? 48 89 6c 24 ?? 44 89 b4 24 ?? 00 00 00 4c 89 74 24 ?? ff 15}  //weight: 20, accuracy: Low
        $x_20_2 = {33 d2 33 c9 c7 44 24 ?? 68 00 00 00 ff 15 ?? ?? ?? ?? 45 33 c9 48 8b d8 48 8d 44 24 ?? 45 33 c0 48 89 44 24 ?? 48 8d 44 24 ?? 33 d2 48 89 44 24 ?? 48 89 74 24 ?? 48 89 74 24 ?? 48 8b cf 89 74 24 ?? 89 74 24 ?? ff 15 8b 0c 00 00 85 c0 74 ?? 48 8b 4c 24 ?? ba 10 27 00 00 ff 15}  //weight: 20, accuracy: Low
        $x_20_3 = {33 c9 8d 50 02 41 b8 00 30 00 00 44 8d 49 04 ff 15}  //weight: 20, accuracy: High
        $x_10_4 = "LPE DLL: Trying to Open Pipe - %ws" ascii //weight: 10
        $x_10_5 = "LPE DLL: Target path: %ws" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 2 of ($x_10_*))) or
            ((3 of ($x_20_*))) or
            (all of ($x*))
        )
}

