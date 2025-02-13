rule Ransom_Win32_CryptLockr_PB_2147828911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryptLockr.PB!MTB"
        threat_id = "2147828911"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptLockr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cipher.psm1" ascii //weight: 1
        $x_1_2 = "$home\\Desktop\\Readme_now.txt" ascii //weight: 1
        $x_1_3 = "Your personal files have been encrypted" ascii //weight: 1
        $x_1_4 = "\\Documents\\WindowsPowerShell\\Modules\\Cipher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

