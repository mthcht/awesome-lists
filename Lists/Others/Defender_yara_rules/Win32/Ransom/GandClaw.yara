rule Ransom_Win32_GandClaw_A_2147729751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GandClaw.A"
        threat_id = "2147729751"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GandClaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {c7 45 e0 99 a9 aa aa 50 57 c7 45 e4 ed fe ad de c7 45 f0 00 00 00 00}  //weight: 20, accuracy: High
        $x_20_2 = {81 7d e0 99 a9 aa aa 75 a2}  //weight: 20, accuracy: High
        $x_20_3 = {0f 57 c0 c7 45 e8 00 00 00 00 68 ?? ?? ?? ?? 6a 00 f3 0f 7f 45 a8 6a 00 8b f1 c7 45 a8 44 00 00 00 f3 0f 7f 45 b8 f3 0f 7f 45 c8 f3 0f 7f 45 d8 f3 0f 7f 45 f0 ff 15 ?? ?? ?? ?? 8b f8 8d 45 f0 50 8d 45 a8 50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 56 ff 15}  //weight: 20, accuracy: Low
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

