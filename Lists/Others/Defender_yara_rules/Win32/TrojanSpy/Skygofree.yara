rule TrojanSpy_Win32_Skygofree_2147725423_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Skygofree"
        threat_id = "2147725423"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Skygofree"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-32] 2f 00 73 00 6b 00 79 00 70 00 65 00 5f 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Downloading File \"{0}\" from \"{1}\" ......." wide //weight: 1
        $x_1_3 = "\\myupd\\skype\\" wide //weight: 1
        $x_1_4 = "\\\\vmware-host\\Shared Folders\\dati\\Backup\\Projects\\REcodin_2\\REcodin_2\\obj\\x86\\Release\\REcodin_2.pdb" ascii //weight: 1
        $x_1_5 = "REcodin_2.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

