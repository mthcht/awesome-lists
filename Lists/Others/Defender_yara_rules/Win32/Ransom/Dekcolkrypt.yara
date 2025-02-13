rule Ransom_Win32_Dekcolkrypt_A_2147726467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dekcolkrypt.A"
        threat_id = "2147726467"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dekcolkrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Windows\\Back.jpg" wide //weight: 2
        $x_2_2 = "decryptor.exe" wide //weight: 2
        $x_2_3 = "Paybit" wide //weight: 2
        $x_2_4 = "conf.txt" wide //weight: 2
        $x_2_5 = ".LCKD" ascii //weight: 2
        $x_2_6 = "BK.jpg" wide //weight: 2
        $x_2_7 = "Your important files are encrypted." wide //weight: 2
        $x_2_8 = "If you save your files, Run and follow the instructions!" wide //weight: 2
        $x_2_9 = "But if you want to decrypt all your files, you need to pay." ascii //weight: 2
        $x_2_10 = "1LXhpinYWzF73hUyDvxApkChq2QfZhm6GA" wide //weight: 2
        $x_2_11 = "PAYMENT WILL BE RAISED ON:" ascii //weight: 2
        $x_2_12 = "YOUR FILES WILL BE LOST ON:" ascii //weight: 2
        $x_2_13 = "decryptorsoon301@aol.com" ascii //weight: 2
        $x_2_14 = "If you fail this time , you can lose your encrypted files" wide //weight: 2
        $x_2_15 = "Enter Correct Key to decrypt your files" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

