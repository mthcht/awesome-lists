rule Trojan_Win32_Allinonekeylogger_PGAK_2147938276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Allinonekeylogger.PGAK!MTB"
        threat_id = "2147938276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Allinonekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c1 33 d2 f7 f6 41 0f b6 82 ?? ?? ?? ?? 03 c3 33 d2 f7 75 fc 8b 45 08 03 de 80 c2 ?? 88 54 08 fe 8b 45 0c 3b cf 7e d8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

