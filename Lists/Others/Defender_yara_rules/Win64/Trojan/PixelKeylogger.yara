rule Trojan_Win64_PixelKeylogger_A_2147893179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PixelKeylogger.A!MTB"
        threat_id = "2147893179"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PixelKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b cb ff 15 ?? ?? 00 00 66 0f ba e0 ?? 72 ?? ff c3 81 fb ?? ?? ?? ?? 7e ?? 8b 1d 46 45 00 00 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

