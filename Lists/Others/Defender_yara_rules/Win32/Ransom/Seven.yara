rule Ransom_Win32_Seven_MAK_2147807780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Seven.MAK!MTB"
        threat_id = "2147807780"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Seven"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"allkeeper\" /t REG_SZ /d" ascii //weight: 1
        $x_1_2 = "REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\" /v \"testdecrypt\" /t REG_SZ /d" ascii //weight: 1
        $x_1_3 = "\\del.bat" ascii //weight: 1
        $x_1_4 = "REG ADD \"HKEY_CURRENT_USER\\SOFTWARE\" /v \"Decrypt50\" /t REG_SZ /d" ascii //weight: 1
        $x_1_5 = "You have to pay within 72 hours" ascii //weight: 1
        $x_1_6 = "important files were encrypted with strong algorithm" ascii //weight: 1
        $x_1_7 = "YOUR PERSONAL FILES WERE ENCRYPTED BY 7ev3n-HONE$T" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

