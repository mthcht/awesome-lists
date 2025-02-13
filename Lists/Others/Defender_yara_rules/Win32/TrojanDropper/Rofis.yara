rule TrojanDropper_Win32_Rofis_2147627424_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rofis"
        threat_id = "2147627424"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rofis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 02 00 00 80 ff [0-5] 0f [0-16] 51 56 6a 03 50 68 ?? ?? ?? ?? 52 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 03 6a 00 6a 07 68 00 00 00 80 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 05 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? ff d0 0f 31}  //weight: 1, accuracy: Low
        $x_1_4 = "sfc.dll" ascii //weight: 1
        $x_1_5 = "RegSetValueExA" ascii //weight: 1
        $x_1_6 = "ShellCode\\xRelease\\ShellCode.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

