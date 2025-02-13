rule Trojan_Win32_GreenMonster_2147811717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GreenMonster.gen!dha"
        threat_id = "2147811717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GreenMonster"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {66 83 b4 45 ?? ?? ?? ?? ?? 40 83 f8 40 72 f1}  //weight: 5, accuracy: Low
        $x_5_2 = {50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 8d 85 ?? ?? ?? ?? 50 6a 00 ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

