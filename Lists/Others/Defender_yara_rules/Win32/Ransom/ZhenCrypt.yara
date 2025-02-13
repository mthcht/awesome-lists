rule Ransom_Win32_ZhenCrypt_AB_2147765899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ZhenCrypt.AB!MTB"
        threat_id = "2147765899"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ZhenCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Read For Decryption.lnk" ascii //weight: 1
        $x_1_2 = "Decryptor.lnk" ascii //weight: 1
        $x_1_3 = "/grant Users:F" ascii //weight: 1
        $x_1_4 = "Payment Checked!" ascii //weight: 1
        $x_1_5 = "how+to+buy+bitcoin" ascii //weight: 1
        $x_1_6 = "\\Desktop\\Decryption Note.txt" ascii //weight: 1
        $x_1_7 = "Send 0.3 BTC To:" ascii //weight: 1
        $x_1_8 = "Zhen!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

