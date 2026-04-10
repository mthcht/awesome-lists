rule Trojan_Win64_LucidRook_GXH_2147966779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LucidRook.GXH!MTB"
        threat_id = "2147966779"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LucidRook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8d 0c 02 c6 04 02 80 48 89 c2 48 83 f2 3f 45 31 c0 4c 39 c2 ?? ?? 42 c6 44 01 ?? 00 49 ff c0}  //weight: 10, accuracy: Low
        $x_1_2 = "BrowserHistoryBrowserLoginsDiscordTokensKeyloggerDumpKeylogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

