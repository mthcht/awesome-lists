rule Ransom_Win64_Alvaro_MA_2147890035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Alvaro.MA!MTB"
        threat_id = "2147890035"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Alvaro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://api.telegram.org/bot" ascii //weight: 1
        $x_1_2 = "/sendMessage?chat_id=" ascii //weight: 1
        $x_1_3 = ".EMAIL = [alvarodecrypt@gmail.com]ID =" ascii //weight: 1
        $x_1_4 = ".alvaro" ascii //weight: 1
        $x_1_5 = "FILE ENCRYPTED.txt" ascii //weight: 1
        $x_1_6 = "To restore the system write to both : alvarodecrypt@gmail.com" ascii //weight: 1
        $x_1_7 = "alvarodecrypt@outlook.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

