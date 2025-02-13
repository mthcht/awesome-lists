rule Trojan_O97M_Prenebevs_2147723725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Prenebevs"
        threat_id = "2147723725"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Prenebevs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Environ(\"SYSTEMDRIVE\")" ascii //weight: 10
        $x_10_2 = "schtasks /create /sc MINUTE /tn \"\"GoogleUpdateTasksMachineCore\"\"" ascii //weight: 10
        $x_10_3 = "\\\"\"sc\\\"\"r\\\"\"i\\\"\"p\\\"\"t:http://80.255.3.109/microsoft.js" ascii //weight: 10
        $x_10_4 = "(\"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CurrentVersion\")" ascii //weight: 10
        $x_10_5 = {46 69 6c 65 43 6f 70 79 20 [0-32] 20 26 20 22 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 77 73 63 72 69 70 74 2e 65 78 65 22 2c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

