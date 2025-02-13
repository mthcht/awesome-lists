rule TrojanDropper_Win32_Exetemp_A_2147718298_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Exetemp.A!bit"
        threat_id = "2147718298"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Exetemp"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 04 01 de 41 3b ca 72 f7}  //weight: 1, accuracy: High
        $x_1_2 = {6a 01 8d 3c 2e 53 53 57 68 ?? ?? ?? ?? 53 ff 15 ?? ?? ?? ?? 57 ff 15 ?? ?? ?? ?? 8d 74 06 01 3b 74 24 20 72}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c4 10 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 0a ff 15 ?? ?? ?? ?? 8b 54 24 ?? 8b 44 24 ?? 83 c2 10 83 c7 20 48 89 54 24 ?? 89 44 24 ?? 75}  //weight: 1, accuracy: Low
        $x_1_4 = "EXE_temp%x%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

