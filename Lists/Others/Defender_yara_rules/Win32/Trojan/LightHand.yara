rule Trojan_Win32_LightHand_A_2147916849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LightHand.A!dha"
        threat_id = "2147916849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LightHand"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {b8 0f 00 00 00 c0 ea 07 0f 1f 00 0f ?? ?? ?? ?? d0 c1 88 ?? ?? ?? 48 ff c8 48 85 c0 7f}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

