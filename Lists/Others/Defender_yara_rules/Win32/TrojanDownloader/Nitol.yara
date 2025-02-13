rule TrojanDownloader_Win32_Nitol_A_2147838018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nitol.A!MTB"
        threat_id = "2147838018"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 64 24 0c 68 19 00 ff 15 04 ?? 40 00 8b f0 68 ?? ?? 40 00 56 ff 15 10 ?? 40 00 51 8b f8 8b cc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Nitol_C_2147896370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nitol.C!MTB"
        threat_id = "2147896370"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nitol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 45 e8 4b c6 45 e9 65 c6 45 ea 72 c6 45 eb 6e c6 45 ec 65 c6 45 ed 6c c6 45 ee 33 c6 45 ef 32 c6 45 f0 2e c6 45 f1 64 c6 45 f2 6c c6 45 f3 6c}  //weight: 2, accuracy: High
        $x_2_2 = {c6 45 b8 56 c6 45 b9 69 c6 45 ba 72 c6 45 bb 74 c6 45 bc 75 c6 45 bd 61 c6 45 be 6c c6 45 bf 41 c6 45 c0 6c c6 45 c1 6c c6 45 c2 6f c6 45 c3 63}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

