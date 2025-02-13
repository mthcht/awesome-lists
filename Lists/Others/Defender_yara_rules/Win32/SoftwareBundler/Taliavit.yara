rule SoftwareBundler_Win32_Taliavit_225384_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Taliavit"
        threat_id = "225384"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Taliavit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 6d 6f 63 6b 75 70 5f 73 6f 66 74 77 61 72 65 75 70 64 61 74 65 72 2e 62 6d 70 00 75 73 65 72 33 32 3a 3a 4c 6f 61 64 49 6d 61 67 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-80] 4f 6e 43 6c 69 63 6b [0-15] 49 6e 73 74 61 6c 61 72 20 42 61 73 65 66 6c 61 73 68}  //weight: 1, accuracy: Low
        $x_1_2 = "/OFFERKEYWORD=baseflash\" \"/OFFERURL=http://dld.baseflash.com/ProtectbaseflashSetup.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Taliavit_225384_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Taliavit"
        threat_id = "225384"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Taliavit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 4f 4b 53 50 26 [0-32] 26 70 6d 64 35 3d [0-144] 5c 62 61 73 65 66 6c 61 73 68 53 65 74 75 70 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_2 = "/protectbaseflash/ProtectbaseflashSetup.exe\" \"/OFFERPARAMS=" ascii //weight: 2
        $x_1_3 = "vitkvitk.com/xmlstatic/installers/" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\ProtectExtension" ascii //weight: 1
        $x_1_5 = "tkDecript.pdb" ascii //weight: 1
        $x_1_6 = {6f 6b 69 74 73 70 61 63 65 00 62 61 73 65 66 6c 61 73 68 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

