rule Trojan_Win64_Tufthook_AP_2147982460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tufthook.AP!MTB"
        threat_id = "2147982460"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tufthook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {41 0f b6 0c 10 8b c3 48 33 c8 0f b6 c1 c1 eb ?? 41 33 1c 83 48 ff c2 49 3b d6 72}  //weight: 15, accuracy: Low
        $x_3_2 = "[LootCollector] total cap reached, skipping" ascii //weight: 3
        $x_2_3 = "[StartGeckoGrabber] Key hex: " ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

