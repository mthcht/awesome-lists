rule Ransom_MSIL_OsnoCrypt_MB_2147765663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/OsnoCrypt.MB!MTB"
        threat_id = "2147765663"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OsnoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RecInstruct.osnoned" ascii //weight: 1
        $x_1_2 = "Osno Ransomware" ascii //weight: 1
        $x_1_3 = "OsnoDebug.txt" ascii //weight: 1
        $x_1_4 = "OsnoGang" ascii //weight: 1
        $x_1_5 = "process.env.hook = 'Osno'" ascii //weight: 1
        $x_1_6 = "Osno Ransomware - How to recover your files" ascii //weight: 1
        $x_1_7 = "Started the ransomware!" ascii //weight: 1
        $x_1_8 = "Started the wifi stealer" ascii //weight: 1
        $x_1_9 = "Brought you by OsnoKeylogger" ascii //weight: 1
        $x_1_10 = "Started the anti-debugger" ascii //weight: 1
        $x_1_11 = "All your files are encrypted by Osno Ransomware!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

