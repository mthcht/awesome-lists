rule Backdoor_MSIL_Facchom_A_2147687542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Facchom.A"
        threat_id = "2147687542"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Facchom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylogger" ascii //weight: 1
        $x_1_2 = "SlowLoris" ascii //weight: 1
        $x_1_3 = "StopFlood" ascii //weight: 1
        $x_1_4 = "SendWebcam" ascii //weight: 1
        $x_1_5 = "sendscreen" ascii //weight: 1
        $x_1_6 = "Startstresser" ascii //weight: 1
        $x_1_7 = "|Chrome|" wide //weight: 1
        $x_1_8 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 1
        $x_1_9 = "/newconnection.php" wide //weight: 1
        $x_1_10 = "message=FileUploadCompleted&file=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

