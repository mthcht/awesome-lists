rule Ransom_Win64_Mineware_QR_2147981332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Mineware.QR.MTB"
        threat_id = "2147981332"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Mineware"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ransommineware" ascii //weight: 3
        $x_2_2 = "Your files have been encrypted by someone" ascii //weight: 2
        $x_2_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_2_4 = "correct password. recovering your files..." ascii //weight: 2
        $x_2_5 = "System Volume Information" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

