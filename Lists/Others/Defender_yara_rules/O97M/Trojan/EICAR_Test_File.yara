rule Trojan_O97M_EICAR_Test_File_KA_2147750840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EICAR_Test_File.KA!MSR"
        threat_id = "2147750840"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EICAR_Test_File"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eicarPart1 = \"X5O!P%@AP[4\\PZX54(P^)7C\"" ascii //weight: 1
        $x_1_2 = "eicarPart2 = \"C)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\"" ascii //weight: 1
        $x_1_3 = "eicarPart1 + eicarPart2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_EICAR_Test_File_KQ_2147905765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/EICAR_Test_File.KQ!MTB"
        threat_id = "2147905765"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "EICAR_Test_File"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eicarPart1 = \"X5O!P%@AP[4\\PZX54(P^^)7C\"" ascii //weight: 1
        $x_1_2 = "eicarPart2 = \"C)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\"" ascii //weight: 1
        $x_1_3 = "Shell \"cmd.exe /K echo \" + eicarPart1 + eicarPart2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

