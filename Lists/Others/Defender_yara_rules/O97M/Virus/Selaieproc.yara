rule Virus_O97M_Selaieproc_A_2147750949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:O97M/Selaieproc.gen!A"
        threat_id = "2147750949"
        type = "Virus"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Selaieproc"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Shell \"C:\\Program Files\\Internet Explorer\\IEXPLORE.EXE \"" ascii //weight: 1
        $x_1_2 = {43 6f 64 65 4d 6f 64 75 6c 65 2e 49 6e 73 65 72 74 4c 69 6e 65 73 20 [0-4] 2c 20 22 53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29}  //weight: 1, accuracy: Low
        $x_1_3 = "Application.StartupPath" ascii //weight: 1
        $x_1_4 = "Application.SendKeys \"%(qtmstv){ENTER}\"" ascii //weight: 1
        $x_1_5 = ".instancesof(\"Win32_Process\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

