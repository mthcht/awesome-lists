rule Ransom_Win32_Tiger44_XT_2147773324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tiger44.XT!MTB"
        threat_id = "2147773324"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiger44"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOW TO BACK YOUR FILES.txt" ascii //weight: 1
        $x_1_2 = "Tiger4444" ascii //weight: 1
        $x_1_3 = "YOUR FILES ARE ENCRYPTED !!!" ascii //weight: 1
        $x_1_4 = "In the letter include your personal ID! Send me this ID in your first email to me!" ascii //weight: 1
        $x_1_5 = "We can give you free test for decrypt few files (NOT VALUE) and assign the price for decryption all files!" ascii //weight: 1
        $x_1_6 = "DO NOT TRY TO DO SOMETHING WITH YOUR FILES BY YOURSELF YOU WILL BRAKE YOUR DATA !!!" ascii //weight: 1
        $x_1_7 = "ATTENTION !!! THIS IS YOUR PERSONAL ID WICH YOU HAVE TO SEND IN FIRST LETTER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

