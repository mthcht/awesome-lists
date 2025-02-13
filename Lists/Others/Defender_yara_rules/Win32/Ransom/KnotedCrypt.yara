rule Ransom_Win32_KnotedCrypt_SN_2147771427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/KnotedCrypt.SN!MTB"
        threat_id = "2147771427"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "KnotedCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%ls-HELP.txt" wide //weight: 1
        $x_1_2 = "To decrypt all your files you have to buy our software: KnotDecryptor" wide //weight: 1
        $x_1_3 = "vssadmin.exe Delete Shadows /All" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

