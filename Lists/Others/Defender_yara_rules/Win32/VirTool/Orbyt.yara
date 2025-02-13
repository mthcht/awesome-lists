rule VirTool_Win32_Orbyt_A_2147602465_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Orbyt.A!dr"
        threat_id = "2147602465"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Orbyt"
        severity = "Critical"
        info = "dr: dropper component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 fc 07 00 00 00 6a 01 ff 15 ?? ?? ?? ?? c7 45 fc 08 00 00 00 c7 85 ?? ?? ff ff ?? ?? ?? ?? c7 85 ?? ?? ff ff 08 00 00 00 8d 95 ?? ?? ff ff 8d 4d ?? ff 15 ?? ?? ?? ?? 6a 00 6a ff}  //weight: 10, accuracy: Low
        $x_10_2 = {c7 45 fc 28 00 00 00 6a ff ff 15 ?? ?? ?? ?? c7 45 fc 29 00 00 00 e8 ?? ?? ff ff 89 85 ?? ?? ff ff ff 15 ?? ?? ?? ?? 6a 01 68 ?? ?? ?? ?? 8d 4d ?? 51}  //weight: 10, accuracy: Low
        $x_2_3 = "Orbz Crypter" wide //weight: 2
        $x_2_4 = "hansirockz" wide //weight: 2
        $x_2_5 = "/\\#/\\" wide //weight: 2
        $x_1_6 = "\\batch.bat" wide //weight: 1
        $x_1_7 = "ModShellExecute" wide //weight: 1
        $x_1_8 = "ientHeStub" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Orbyt_B_2147608369_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Orbyt.B!dr"
        threat_id = "2147608369"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Orbyt"
        severity = "Critical"
        info = "dr: dropper component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 72 6d 4d 61 69 6e 00 4d 6f 64 53 68 65 6c 6c 45 78 65 63 75 74 65 00 4d 6f 64 52 43 34 00 00 4d 6f 64 48 69 64 65 41 70 70 00 00 4d 6f 64 47 6c 6f 62 61 6c 00 00 00 4d 6f 64 44 69 72 45 78 69 73 74 73 00}  //weight: 10, accuracy: High
        $x_1_2 = "Orbz Crypter" wide //weight: 1
        $x_1_3 = "hansirockz" wide //weight: 1
        $x_1_4 = "/\\#/\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

