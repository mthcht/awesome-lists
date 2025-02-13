rule Trojan_O97M_Emeka_A_2147741116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Emeka.A"
        threat_id = "2147741116"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Emeka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Appdata\\Local\\Microsoft\\Office\\World.bat" ascii //weight: 1
        $x_1_2 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 [0-2] 3a 2f 2f [0-48] 2f 62 61 74 33 2e 74 78 74 22 2c 20 46 61 6c 73 65}  //weight: 1, accuracy: Low
        $x_1_3 = ".savetofile fpFont, 2" ascii //weight: 1
        $x_1_4 = "objW.Get(\"Win32_ProcessStartup\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

