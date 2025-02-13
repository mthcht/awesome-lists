rule Trojan_Win32_Vbedox_A_2147709741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbedox.A"
        threat_id = "2147709741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbedox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Projets\\vbsedit_source\\script2exe\\Release\\mywscript.pdb" ascii //weight: 1
        $x_1_2 = "objShell.run \"cmd /K \"&rim &sim &gim &vim,0" wide //weight: 1
        $x_1_3 = {4f 00 70 00 65 00 6e 00 22 00 47 00 45 00 54 00 22 00 2c 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 75 00 70 00 70 00 6f 00 72 00 74 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-32] 2e 00 70 00 68 00 70 00 2f 00 [0-32] 2e 00 70 00 68 00 70 00 2f 00 63 00 73 00 72 00 73 00 73 00 73 00 2e 00 70 00 68 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = "SaveToFile \"c:/SystemVolume/Program/csrsss.exe" wide //weight: 1
        $x_1_5 = "attrib +s +h c:\\SystemVolume & chdir" wide //weight: 1
        $x_1_6 = "reg add \"\"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"\" /v Adobe /t REG_SZ /d c:\\SystemVolume\\Program\\csrsss.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

