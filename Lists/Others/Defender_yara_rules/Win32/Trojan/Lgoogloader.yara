rule Trojan_Win32_Lgoogloader_GFK_2147841956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lgoogloader.GFK!MTB"
        threat_id = "2147841956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lgoogloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a d1 8b 85 ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 02 05 ?? ?? ?? ?? 32 c2 a2 ?? ?? ?? ?? 8a 45 9c 0f be f0}  //weight: 10, accuracy: Low
        $x_10_2 = {66 33 c1 8b 4d a8 0f b7 d0 8b 45 ac 66 2b d1 66 8b 4d b8 0f b7 c9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

