rule Ransom_Win32_Cryptor_PA_2147741178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryptor.PA!MTB"
        threat_id = "2147741178"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files (documents, photos, videos) were encrypted" ascii //weight: 1
        $x_1_2 = "aaa_TouchMeNot_.txt" wide //weight: 1
        $x_1_3 = "TEMP\\Simple_Encoder\\wallpaper.jpg" wide //weight: 1
        $x_1_4 = "_RECOVER_INSTRUCTIONS.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

