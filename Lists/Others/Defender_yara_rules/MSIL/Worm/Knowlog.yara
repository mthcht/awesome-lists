rule Worm_MSIL_Knowlog_A_2147656944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Knowlog.A"
        threat_id = "2147656944"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Knowlog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Unknown Logger " ascii //weight: 1
        $x_1_2 = "Chrome_Killer" ascii //weight: 1
        $x_1_3 = "SpreadBGWusb_DoWork" ascii //weight: 1
        $x_1_4 = "CD_KeysStealer" ascii //weight: 1
        $x_1_5 = "CIEPassword" ascii //weight: 1
        $x_1_6 = "CMSNMessengerPassword" ascii //weight: 1
        $x_1_7 = "DesverKaspersky" ascii //weight: 1
        $x_1_8 = "GetSteamUsername" ascii //weight: 1
        $x_1_9 = "\\IntelliForms\\Storage1" wide //weight: 1
        $x_1_10 = "\\FTP\\Accounts" wide //weight: 1
        $x_1_11 = "\\Google\\Chrome\\User Data\\Default\\Cookies" wide //weight: 1
        $x_1_12 = "\\Mozilla\\Firefox\\Profiles" wide //weight: 1
        $x_1_13 = {5b 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 5d 00 0d 00 0a 00 73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00}  //weight: 1, accuracy: High
        $x_1_14 = "\\ClientRegistry.blob" wide //weight: 1
        $x_1_15 = "\\Electronic Arts\\EA " wide //weight: 1
        $x_1_16 = "\\kazaa\\my shared folder\\" wide //weight: 1
        $x_1_17 = "\\limewire\\shared\\" wide //weight: 1
        $x_1_18 = "select * from win32_share" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule Worm_MSIL_Knowlog_B_2147658516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Knowlog.B"
        threat_id = "2147658516"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Knowlog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 68 61 72 65 61 7a 61 53 74 61 72 74 00 45 6d 75 6c 65 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "getMSN75Passwords" ascii //weight: 1
        $x_1_3 = "DesverMalwarebytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_MSIL_Knowlog_C_2147670466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Knowlog.C"
        threat_id = "2147670466"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Knowlog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 65 74 4d 53 4e 37 35 50 61 73 73 77 6f 72 64 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 5f 4d 53 4e 50 61 73 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {6c 61 6e 69 6e 66 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {67 65 74 5f 4c 6f 67 69 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 70 72 65 61 64 5f 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

