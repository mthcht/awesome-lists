rule TrojanDownloader_Win32_Cofas_A_2147852656_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cofas.A!MTB"
        threat_id = "2147852656"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cofas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 f7 d8 1b c0 25 ?? ?? 40 00 50 a1 ?? ?? 40 00 f7 d9 1b c9 81 e1 ?? ?? 40 00 51 8b 0d ?? ?? 40 00 68 ?? ?? 40 00 6a 00 6a 00 68 ?? ?? 40 00 52 8b 15 ?? ?? 40 00 50 51 52 68}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

