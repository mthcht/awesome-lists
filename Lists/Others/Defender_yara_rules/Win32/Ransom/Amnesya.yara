rule Ransom_Win32_Amnesya_SK_2147761370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Amnesya.SK!MTB"
        threat_id = "2147761370"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Amnesya"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "THE FILE IS ENCRYPTED WITH THE RSA-2048 ALGORITHM, ONLY WE CAN DECRYPT THE FILE" ascii //weight: 1
        $x_1_2 = "Your files are encrypted!" ascii //weight: 1
        $x_1_3 = "IF YOU DO NOT HAVE A JABBER. TO WRITE TO US TO REGISTER" ascii //weight: 1
        $x_5_4 = "system32.exe" ascii //weight: 5
        $x_5_5 = "[/TASKNAME][AUTOEXEC][README]HOW TO RECOVE" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

