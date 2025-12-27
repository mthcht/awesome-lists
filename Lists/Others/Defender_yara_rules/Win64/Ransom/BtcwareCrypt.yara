rule Ransom_Win64_BtcwareCrypt_PA_2147952411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BtcwareCrypt.PA!MTB"
        threat_id = "2147952411"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BtcwareCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "rmdir /s /q C:\\Windows\\System32 2>nul" ascii //weight: 1
        $x_3_3 = "YOUR SYSTEM HAS BEEN TAKEN OVER BY WHO-AM-I-404" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

