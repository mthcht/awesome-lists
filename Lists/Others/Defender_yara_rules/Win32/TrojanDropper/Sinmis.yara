rule TrojanDropper_Win32_Sinmis_A_2147646606_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sinmis.A"
        threat_id = "2147646606"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinmis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 3a 32 0c 2e 83 c6 01 88 0a 83 c2 01 80 3c 2e 00 75 02 33 f6}  //weight: 1, accuracy: High
        $x_1_2 = {80 c2 61 88 14 3e 83 c6 01 3b f5 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sinmis_B_2147647991_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sinmis.B"
        threat_id = "2147647991"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinmis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 65 78 65 c6 80 ?? ?? ?? ?? 00 31 c0 6a 04 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 40 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {31 c0 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? 00 00 4d 5a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

