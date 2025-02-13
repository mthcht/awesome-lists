rule Backdoor_MacOS_X_HackBack_A_2147681628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/HackBack.A"
        threat_id = "2147681628"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "HackBack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "FileBackup.ini" ascii //weight: 2
        $x_2_2 = {63 68 65 63 6b 41 75 74 6f 72 75 6e [0-5] 61 70 70 6c 69 63 61 74 69 6f 6e 57 69 6c 6c 54 65 72 6d 69 6e 61 74 65 3a}  //weight: 2, accuracy: Low
        $x_2_3 = "m_ComputerName_UserName" ascii //weight: 2
        $x_2_4 = "m_uploadURL" ascii //weight: 2
        $x_2_5 = "m_FolderList" ascii //weight: 2
        $x_2_6 = "connectserver_callback" ascii //weight: 2
        $x_2_7 = {44 61 74 65 2e 64 61 74 00 46 61 69 6c 2e 64 61 74}  //weight: 2, accuracy: High
        $x_2_8 = "/upload.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

