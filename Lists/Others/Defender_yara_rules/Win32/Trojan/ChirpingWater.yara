rule Trojan_Win32_ChirpingWater_A_2147924994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ChirpingWater.A!dha"
        threat_id = "2147924994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ChirpingWater"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 8d 0c 1f 99 47 f7 fe 8b 45 ?? 8a 04 02 8b 55 ?? 32 04 0a 88 01 8b 45 ?? 3b f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

