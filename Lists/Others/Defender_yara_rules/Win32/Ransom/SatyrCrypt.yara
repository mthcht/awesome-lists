rule Ransom_Win32_SatyrCrypt_SJ_2147773660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SatyrCrypt.SJ!MTB"
        threat_id = "2147773660"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SatyrCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "All your data has been locked us." wide //weight: 2
        $x_2_2 = "You have to pay for decryption in Bitcoins." wide //weight: 2
        $x_2_3 = "vssadmin.exe delete shadows /all /quiet" wide //weight: 2
        $x_2_4 = "Your personal ID KEY:" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

