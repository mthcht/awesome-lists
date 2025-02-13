rule Trojan_O97M_Namunigan_A_2147707161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Namunigan.A"
        threat_id = "2147707161"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Namunigan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ExecQuery(\"Select * From Win32_NetworkAdapterConfiguration Where IPEnabled = True\")" ascii //weight: 1
        $x_1_2 = "strMsgBox = strMsgBox & \"IP Address: \" & strIP & \"; \"" ascii //weight: 1
        $x_1_3 = "= \"http://\" &" ascii //weight: 1
        $x_1_4 = "& \".xyz:\" &" ascii //weight: 1
        $x_1_5 = "UserDomain & \"\\\" & objNet.UserName & \"\\; \" & IP & soft" ascii //weight: 1
        $x_1_6 = "Media Center PC 5.0; .NET CLR 1.1.4322; .NET CLR 3.5.30729)### \" & objNet.ComputerName & \"; \" &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

