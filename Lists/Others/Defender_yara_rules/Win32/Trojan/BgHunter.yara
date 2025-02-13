rule Trojan_Win32_BgHunter_2147811720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BgHunter.gen!dha"
        threat_id = "2147811720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BgHunter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 43 44 13 c7 ?? ?? d6 bc 8e db c7 ?? ?? aa 9e 9f 12 c7 ?? ?? c5 ba db c1 c7 ?? ?? 67 24 1f b0 c7 ?? ?? 41 d5 a5 bb c7 ?? ?? 7f 11 39 fe}  //weight: 5, accuracy: Low
        $x_5_2 = {0f b6 04 32 8d 76 01 34 64 88 46 ff 0f b6 44 37 ff 34 64 88 86 33 04 00 00 83 e9 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

