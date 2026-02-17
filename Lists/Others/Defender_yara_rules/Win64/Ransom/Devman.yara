rule Ransom_Win64_Devman_C_2147956982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Devman.C"
        threat_id = "2147956982"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Devman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Path to the directory to encrypt (can be before or after flags)" ascii //weight: 1
        $x_1_2 = "Encrypting only provided path(s):" ascii //weight: 1
        $x_1_3 = "Error: failed to initialize crypto backend" ascii //weight: 1
        $x_1_4 = "Starting local encryption..." ascii //weight: 1
        $x_1_5 = "Failed to create README:" ascii //weight: 1
        $x_1_6 = "data_encryptor started with args:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win64_Devman_D_2147961078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Devman.D"
        threat_id = "2147961078"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Devman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DEVMAN File Encryption Utility" ascii //weight: 1
        $x_1_2 = "Encryption complete. Files encrypted: " ascii //weight: 1
        $x_1_3 = "Successfully encrypted drive: " ascii //weight: 1
        $x_1_4 = "Failed to set wallpaper:" ascii //weight: 1
        $x_1_5 = "Dropped ransom note at: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Devman_AB_2147963159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Devman.AB!MTB"
        threat_id = "2147963159"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Devman"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
        $x_1_2 = "DEVMAN 3.0" ascii //weight: 1
        $x_1_3 = "1. Find !!!_READ_ME_!!!.txt on your desktop" ascii //weight: 1
        $x_1_4 = "schtasks /create /s $pc /u $u /p $p /tn $tn /tr \"C:\\ProgramData\\$name\" /sc once /st 00:00 /ru SYSTEM /f 2>$null" ascii //weight: 1
        $x_1_5 = "and backups have been locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

