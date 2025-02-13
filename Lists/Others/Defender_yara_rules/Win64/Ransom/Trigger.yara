rule Ransom_Win64_Trigger_F_2147749990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Trigger.F"
        threat_id = "2147749990"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Trigger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.scanDir" ascii //weight: 1
        $x_1_2 = "main.encryptFile" ascii //weight: 1
        $x_1_3 = "main.makeReadmeFile" ascii //weight: 1
        $x_1_4 = "main.writeLog" ascii //weight: 1
        $x_1_5 = "main.encryptFile.func1" ascii //weight: 1
        $x_1_6 = "main.makeReadmeFile.func1" ascii //weight: 1
        $x_1_7 = "main.writeLog.func1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

