rule Trojan_O97M_Syscon_A_2147723738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Syscon.A"
        threat_id = "2147723738"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Syscon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "nResult = Shell(\"cmd /c expand %TEMP%\\setup.cab -F:*" ascii //weight: 1
        $x_1_2 = {26 26 20 64 65 6c 20 2f 66 20 2f 71 [0-16] 73 65 74 75 70 2e 63 61 62 20 26 26}  //weight: 1, accuracy: Low
        $x_1_3 = "GetObject(\"Winmgmts:\").ExecQuery" ascii //weight: 1
        $x_1_4 = "IsWin32OrWin64 = \"Win\" & info.AddressWidth" ascii //weight: 1
        $x_1_5 = "Sub Document_Open()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

