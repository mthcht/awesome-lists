rule Ransom_Win32_Pocrimcrypt_A_2147714333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Pocrimcrypt.A!!Pocrimcrypt.gen!A"
        threat_id = "2147714333"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Pocrimcrypt"
        severity = "Critical"
        info = "Pocrimcrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lock." wide //weight: 1
        $x_1_2 = "_crypt_encryptfile" wide //weight: 1
        $x_2_3 = "\\microcop.lnk" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

