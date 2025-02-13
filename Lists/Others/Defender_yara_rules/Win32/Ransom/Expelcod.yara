rule Ransom_Win32_Expelcod_A_2147720882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Expelcod.A"
        threat_id = "2147720882"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Expelcod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutoEncryptor" ascii //weight: 1
        $x_1_2 = "UserFilesLocker.exe" wide //weight: 1
        $x_1_3 = "__encrypt.pinfo" wide //weight: 1
        $x_1_4 = ".ENCR" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

