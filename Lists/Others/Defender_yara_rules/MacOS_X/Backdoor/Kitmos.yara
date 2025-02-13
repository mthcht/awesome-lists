rule Backdoor_MacOS_X_Kitmos_A_2147681629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS_X/Kitmos.A"
        threat_id = "2147681629"
        type = "Backdoor"
        platform = "MacOS_X: "
        family = "Kitmos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/usr/sbin/screencapture" ascii //weight: 2
        $x_2_2 = "/bin/sh" ascii //weight: 2
        $x_2_3 = "/usr/bin/curl" ascii //weight: 2
        $x_2_4 = "X-ASIHTTPRequest-Expires" ascii //weight: 2
        $x_2_5 = "m_FolderList" ascii //weight: 2
        $x_2_6 = "m_zipUpload" ascii //weight: 2
        $x_2_7 = "m_ComputerName_UserName" ascii //weight: 2
        $x_2_8 = "m_uploadURL" ascii //weight: 2
        $x_2_9 = "/lang.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

