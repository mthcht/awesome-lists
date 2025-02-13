rule Trojan_Win32_AutoitGenome_RA_2147836565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitGenome.RA!MTB"
        threat_id = "2147836565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitGenome"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Http://W347302.S98.Ufhosted.Com/serverip.txt" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\Managemenot\\Monitor\\tcpscrex.exe" ascii //weight: 1
        $x_1_3 = "Http://W347302.S98.Ufhosted.Com/UP/Down.txt" ascii //weight: 1
        $x_1_4 = "REGREAD ( \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" , \"Rescue\"" ascii //weight: 1
        $x_1_5 = "CurrentVersion\\Run\" , \"Rescue\" , \"REG_SZ\" , @PROGRAMFILESDIR & \"\\Activxr\\Rescue.exe\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitGenome_RA_2147836565_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitGenome.RA!MTB"
        threat_id = "2147836565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitGenome"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_KAIXRANDOM ( 10 , 0 , 9 )" ascii //weight: 1
        $x_1_2 = "http://www.aamailsoft.com/getip.php" ascii //weight: 1
        $x_1_3 = "Rescuer.exe" ascii //weight: 1
        $x_1_4 = "Http://W347302.S98.Ufhosted.Com/NC/Server.txt" ascii //weight: 1
        $x_1_5 = " _KAIXFILESETTIME ( @SCRIPTDIR & \"\\Recovery.exe\" , \"20040817120000\" )" ascii //weight: 1
        $x_1_6 = "ADLIBUNREGISTER ( \"MianSha360\"" ascii //weight: 1
        $x_1_7 = "CurrentVersion\\Run\" , \"Rescue\" , \"REG_SZ\" , @PROGRAMFILESDIR & \"\\Activxr\\Rescue.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

