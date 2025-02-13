rule Trojan_Java_AdwindAY_B_2147755728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/AdwindAY.B!MTB"
        threat_id = "2147755728"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "AdwindAY"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Desktop.jar" ascii //weight: 1
        $x_1_2 = "REG ADD HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Desktop /d" ascii //weight: 1
        $x_1_3 = "DIRECTORYUP" ascii //weight: 1
        $x_1_4 = "CHNGDIR" ascii //weight: 1
        $x_1_5 = "Client/.mauscs" ascii //weight: 1
        $x_1_6 = "localhost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

