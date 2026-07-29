rule Trojan_Win64_TinyEgg_GTX_2147974760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TinyEgg.GTX!MTB"
        threat_id = "2147974760"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TinyEgg"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b9 80 00 00 00 c7 84 24 ?? ?? ?? ?? 00 01 00 00 f3 ab b9 80 00 00 00 48 8d bc 24 ?? ?? ?? ?? 48 8d 94 24 ?? ?? ?? ?? f3 ab 48 8d 84 24 ?? ?? ?? ?? c7 84 24 ?? ?? ?? ?? 00 01 00 00 48 89 c1 48 89 84 24 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8d 84 24 ?? ?? ?? ?? 48 8d 94 24 ?? ?? ?? ?? 48 89 c1 48 89 44 24 ?? ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {05 e7 03 00 00 89 c0 48 69 c0 d3 4d 62 10 48 c1 e8 20 c1 e8 06 89 c1 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 5, accuracy: Low
        $x_2_3 = "updater.dll" ascii //weight: 2
        $x_2_4 = "DllInstall" ascii //weight: 2
        $x_2_5 = "ixwebsocket::heartbeat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

