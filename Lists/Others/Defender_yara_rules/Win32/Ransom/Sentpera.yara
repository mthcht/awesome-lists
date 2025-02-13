rule Ransom_Win32_Sentpera_A_2147723704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sentpera.A!!Sentpera.gen!A"
        threat_id = "2147723704"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sentpera"
        severity = "Critical"
        info = "Sentpera: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "encryptionsoftware.exe" ascii //weight: 10
        $x_10_2 = "RSACryptoServiceProvider" ascii //weight: 10
        $x_10_3 = "RijndaelManaged" ascii //weight: 10
        $x_10_4 = "encryptionsoftware.Resources.resources" ascii //weight: 10
        $x_10_5 = "get_TotalPhysicalMemory" ascii //weight: 10
        $x_10_6 = "get_UserName" ascii //weight: 10
        $x_10_7 = "get_FileSystem" ascii //weight: 10
        $x_10_8 = "get_SpecialDirectories" ascii //weight: 10
        $x_10_9 = "get_MyDocuments" ascii //weight: 10
        $x_10_10 = "get_MyPictures" ascii //weight: 10
        $x_10_11 = "get_Desktop" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

