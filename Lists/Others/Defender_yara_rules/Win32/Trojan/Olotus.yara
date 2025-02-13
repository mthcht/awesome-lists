rule Trojan_Win32_Olotus_A_2147734673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Olotus.A!dha"
        threat_id = "2147734673"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Olotus"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E:\\ProjectGit\\SHELL\\BrokenSheild\\BrokenShieldPrj\\Bin\\x86\\Release\\DllExportx86.pdb" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Meister\\Documents\\Projects\\BrokenShield\\Bin\\x86\\Release\\BrokenShield.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

