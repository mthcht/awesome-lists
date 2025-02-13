rule Ransom_Win64_SethLocker_PA_2147773279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/SethLocker.PA!MTB"
        threat_id = "2147773279"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "SethLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".seth" ascii //weight: 1
        $x_1_2 = "%USERPROFILE%\\Desktop\\HOW_DECRYPT_FILES.seth.txt" ascii //weight: 1
        $x_1_3 = "%appdata%\\codebind.bat" ascii //weight: 1
        $x_1_4 = "Title Seth Locker" ascii //weight: 1
        $x_1_5 = "Oops, Your Files Have Been Encrypted!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

