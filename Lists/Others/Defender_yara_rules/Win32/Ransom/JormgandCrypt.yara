rule Ransom_Win32_JormgandCrypt_PB_2147779629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/JormgandCrypt.PB!MTB"
        threat_id = "2147779629"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "JormgandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID: \"P4z8W_zE_Z1dBq9diUQ7/ZEWD0EbqrBj-4XIMJl-o/wmKXC0C-fvJC0y_Endgh/24FUsZkSqEY6b6UrreeX" ascii //weight: 1
        $x_1_2 = ".glock" ascii //weight: 1
        $x_1_3 = "Jormungand" ascii //weight: 1
        $x_1_4 = "stoptheworld" ascii //weight: 1
        $x_1_5 = "taskkill.exe" ascii //weight: 1
        $x_1_6 = "READ-ME-NOW.txt" ascii //weight: 1
        $x_1_7 = "Jormungand/main.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

