rule Ransom_Win32_BabukAgent_PA_2147787437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BabukAgent.PA!MTB"
        threat_id = "2147787437"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BabukAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You suck" ascii //weight: 1
        $x_1_2 = "Ha Ha HA !" ascii //weight: 1
        $x_1_3 = "AdwTest.exe" wide //weight: 1
        $x_1_4 = "\\stop-adw.txt" ascii //weight: 1
        $x_1_5 = "m a bad mother fucker !" ascii //weight: 1
        $x_1_6 = "You realy think you can escape me" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

