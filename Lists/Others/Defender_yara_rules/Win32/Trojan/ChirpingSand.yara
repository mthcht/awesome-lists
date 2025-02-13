rule Trojan_Win32_ChirpingSand_A_2147924995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ChirpingSand.A!dha"
        threat_id = "2147924995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ChirpingSand"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8d 0c 3e 8b c6 46 f7 75 ?? 8a 82 ?? ?? ?? ?? 8b 55 ?? 32 04 0a 88 01 3b f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

