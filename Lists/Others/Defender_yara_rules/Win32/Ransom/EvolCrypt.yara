rule Ransom_Win32_EvolCrypt_PAA_2147793525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/EvolCrypt.PAA!MTB"
        threat_id = "2147793525"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "EvolCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c timeout 1 && del \"%s\" >> NUL" wide //weight: 1
        $x_1_2 = "All your data have been encrypted" wide //weight: 1
        $x_1_3 = "backupevolution@tuta.io" wide //weight: 1
        $x_1_4 = ".evolution" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

