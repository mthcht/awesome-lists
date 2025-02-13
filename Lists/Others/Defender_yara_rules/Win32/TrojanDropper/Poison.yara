rule TrojanDropper_Win32_Poison_B_2147649867_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Poison.B"
        threat_id = "2147649867"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 2
        $x_2_2 = "URLDownloadToFileA" ascii //weight: 2
        $x_2_3 = "&&userName=" ascii //weight: 2
        $x_2_4 = "FLASH" wide //weight: 2
        $x_1_5 = "http://xiaoiboxip.appspot.com/" ascii //weight: 1
        $x_1_6 = "fuck?hostname=" ascii //weight: 1
        $x_1_7 = "&&systemcpoy=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Poison_E_2147692681_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Poison.E!dha"
        threat_id = "2147692681"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Poison"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 1f 00 02 00 8d 45 b8 53 50 68 01 00 00 80 ff d7 8b 35 ?? ?? ?? ?? 8b f8 ff d6 83 f8 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {53 50 68 00 40 01 00 68 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 4d ff 75 fc c6 05 ?? ?? ?? ?? 5a c6 05 ?? ?? ?? ?? 90 ff 15 ?? ?? ?? ?? ff d6 83 f8 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

