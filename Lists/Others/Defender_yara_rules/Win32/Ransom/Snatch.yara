rule Ransom_Win32_Snatch_PA_2147746186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Snatch.PA!MTB"
        threat_id = "2147746186"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Snatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your all your files are encrypted and only I can decrypt them." ascii //weight: 1
        $x_1_2 = "The header of the letter must contain the extension of the encryptor" ascii //weight: 1
        $x_1_3 = "You may be a victim of fraud." ascii //weight: 1
        $x_1_4 = "README_5OAXN_DATA.txt" ascii //weight: 1
        $x_1_5 = "/root/go/src/snatch/config.go" ascii //weight: 1
        $x_1_6 = "/root/go/src/snatch/services.go" ascii //weight: 1
        $x_1_7 = "/root/go/src/snatch/main.go" ascii //weight: 1
        $x_1_8 = "/root/go/src/snatch/loger.go" ascii //weight: 1
        $x_1_9 = "/root/go/src/snatch/files.go" ascii //weight: 1
        $x_1_10 = "/root/go/src/snatch/dirs.go" ascii //weight: 1
        $x_1_11 = "main.stopingService" ascii //weight: 1
        $x_1_12 = "main.encryptFile.func" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Snatch_SA_2147763584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Snatch.SA!MTB"
        threat_id = "2147763584"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Snatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Any attempt by any person to decrypt the files or bruteforce the key will be futile and lead to loss of time and precious data" ascii //weight: 1
        $x_1_2 = "Your files have been encrypted using AES 256 key bit algorithm and the password encrypted with a 4096 bit RSA public key" ascii //weight: 1
        $x_1_3 = "Adios Muchachoz!!!" ascii //weight: 1
        $x_1_4 = "-----BEGIN RSA PUBLIC KEY-----" ascii //weight: 1
        $x_1_5 = "Go build ID:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Snatch_MK_2147772876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Snatch.MK!MTB"
        threat_id = "2147772876"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Snatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "*.bak*.csv*.dat*.dbf*.jpg*.png*.rar*.sql*.txt*.xls*.zip" ascii //weight: 1
        $x_1_3 = "hijacked" ascii //weight: 1
        $x_1_4 = "Decrypt.txt" ascii //weight: 1
        $x_1_5 = "Encrypted files:" ascii //weight: 1
        $x_1_6 = "Personal Key:" ascii //weight: 1
        $x_1_7 = "DEK-InfoDNS" ascii //weight: 1
        $x_1_8 = ".encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Snatch_MK_2147772876_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Snatch.MK!MTB"
        threat_id = "2147772876"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Snatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GEHENNA-KEY-README.txt" ascii //weight: 1
        $x_1_2 = "GEHENNA-README-WARNING.html" ascii //weight: 1
        $x_1_3 = "IT IS IMPOSSIBLE TO GET YOUR FILES BACK WITHOUT OUR SPECIAL DECRYPTION TOOL" ascii //weight: 1
        $x_1_4 = "-----END" ascii //weight: 1
        $x_1_5 = "-----BEGIN" ascii //weight: 1
        $x_1_6 = "G-E-H-E-N-N-A" ascii //weight: 1
        $x_1_7 = "ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Snatch_MA_2147847718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Snatch.MA!MTB"
        threat_id = "2147847718"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Snatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /All /Quiet" ascii //weight: 1
        $x_1_2 = "delete catalog - quiet" ascii //weight: 1
        $x_1_3 = "N-A-S-A-C-R-Y" ascii //weight: 1
        $x_1_4 = "RECOVER-FILES-README-WARNING" ascii //weight: 1
        $x_1_5 = "-KEY-README.txt" ascii //weight: 1
        $x_1_6 = "ENCRYPTED-FILES-ALL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

