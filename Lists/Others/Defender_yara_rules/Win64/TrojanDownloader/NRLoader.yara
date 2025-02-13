rule TrojanDownloader_Win64_NRLoader_A_2147889164_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/NRLoader.A!MTB"
        threat_id = "2147889164"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "NRLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 33 c4 48 89 45 f8 45 33 ?? 48 8d 15 ?? 21 00 00 33 c9 ff 15 ?? 1f 00 00 48 8d 0d ?? 21 00 00 ff 15 ?? 1f 00 00 4c 8b f8}  //weight: 2, accuracy: Low
        $x_2_2 = "NightRustClient" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

