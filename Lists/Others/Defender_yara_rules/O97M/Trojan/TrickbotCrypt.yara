rule Trojan_O97M_TrickbotCrypt_SI_2147771881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/TrickbotCrypt.SI!MTB"
        threat_id = "2147771881"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TrickbotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 70 65 6e 22 63 3a 5c [0-21] 5c [0-21] 2e 76 62 65 22 66 6f 72 6f 75 74 70 75 74 61 63 63 65 73 73 77 72 69 74 65 61 73}  //weight: 1, accuracy: Low
        $x_1_2 = {73 68 63 72 65 61 74 65 64 69 72 65 63 74 6f 72 79 65 78 30 2c [0-15] 2c 62 79 76 61 6c 30 26}  //weight: 1, accuracy: Low
        $x_1_3 = "privatedeclareptrsafefunctionshcreatedirectoryexlib\"shell32.dll\"alias\"shcreatedirectoryexa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

