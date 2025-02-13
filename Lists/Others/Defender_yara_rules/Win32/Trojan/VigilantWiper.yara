rule Trojan_Win32_VigilantWiper_RD_2147832520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VigilantWiper.RD!MTB"
        threat_id = "2147832520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VigilantWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c0 56 8b f1 85 d2 74 ?? 0f 1f 80 00 00 00 00 51 33 cb 59 8b c8 83 e1 03 8a 89 ?? ?? ?? ?? 30 0c 30 40 3b c2 72 e9 5e c3}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 51 53 56 57 83 ec 08 ba 00 7a 04 00 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba 7e 07 00 00 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 08 6a 40 68 00 30 00 00 52 6a 00 ff 15 ?? ?? ?? ?? b9 df 01 00 00 89 45 fc be ?? ?? ?? ?? 8b f8 f3 a5 66 a5 b8 ?? ?? ?? ?? 50 8a d8 22 e4 66 c1 e3 4e b6 16 32 d0 8a fe 66 8b da bf ?? ?? ?? ?? 60 32 cb c0 e7 5a 66 83 d9 48 32 fe 66 c1 e3 5f 66 0b db 61 8b c7 50 5e 58 50 6a 00 8b 45 fc 8b d0 81 c2 84 01 00 00 52 58 48 83 e8 02 56 ff d0 6a 00 ff 15 ?? ?? ?? ?? cc cc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

