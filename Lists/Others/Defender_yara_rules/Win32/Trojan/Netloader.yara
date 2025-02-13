rule Trojan_Win32_Netloader_GKH_2147850657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Netloader.GKH!MTB"
        threat_id = "2147850657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Netloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c6 85 68 f9 ff ff 49 c6 85 69 f9 ff ff 6e c6 85 6a f9 ff ff 74 c6 85 6b f9 ff ff 65 c6 85 6c f9 ff ff 72 c6 85 6d f9 ff ff 6e c6 85 6e f9 ff ff 65 c6 85 6f f9 ff ff 74 c6 85 70 f9 ff ff 52 c6 85 71 f9 ff ff 65 c6 85 72 f9 ff ff 61 c6 85 73 f9 ff ff 64 c6 85 74 f9 ff ff 46 c6 85 75 f9 ff ff 69 c6 85 76 f9 ff ff 6c c6 85 77 f9 ff ff 65 c6 85 78 f9 ff ff 00 6a 00 6a 00 6a 00 6a 00 8d 8d ?? ?? ?? ?? 51 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

