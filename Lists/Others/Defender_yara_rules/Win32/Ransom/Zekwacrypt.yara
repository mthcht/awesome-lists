rule Ransom_Win32_Zekwacrypt_A_2147711933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zekwacrypt.A"
        threat_id = "2147711933"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zekwacrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypted_list.txt" ascii //weight: 1
        $x_1_2 = "encrypted_readme.txt" ascii //weight: 1
        $x_1_3 = "datakey.txt" ascii //weight: 1
        $x_1_4 = "Root/desktop file, will process later..." ascii //weight: 1
        $x_1_5 = "EXCEPTION!!! Cannot encrypt file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

