rule TrojanSpy_MSIL_Grelog_A_2147696775_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Grelog.A"
        threat_id = "2147696775"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Grelog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stealer Web" wide //weight: 1
        $x_1_2 = "GreyLogger" wide //weight: 1
        $x_1_3 = "/remote_dl.php" wide //weight: 1
        $x_1_4 = "/remote_dlurl.php" wide //weight: 1
        $x_1_5 = "/remote_blacklist.php" wide //weight: 1
        $x_1_6 = "Ankama Shield" wide //weight: 1
        $x_1_7 = "KeyLog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

