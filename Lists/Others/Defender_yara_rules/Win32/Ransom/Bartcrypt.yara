rule Ransom_Win32_Bartcrypt_A_2147714357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Bartcrypt.A"
        threat_id = "2147714357"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Bartcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 65 63 6f 76 65 72 2e 74 78 74 00}  //weight: 2, accuracy: High
        $x_2_2 = {5c 72 65 63 6f 76 65 72 2e 62 6d 70 00}  //weight: 2, accuracy: High
        $x_1_3 = {2e 62 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "Decrypting of your files is only possible" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Bartcrypt_A_2147714358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Bartcrypt.A!!Bartcrypt.gen!A"
        threat_id = "2147714358"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Bartcrypt"
        severity = "Critical"
        info = "Bartcrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 65 63 6f 76 65 72 2e 74 78 74 00}  //weight: 2, accuracy: High
        $x_2_2 = {5c 72 65 63 6f 76 65 72 2e 62 6d 70 00}  //weight: 2, accuracy: High
        $x_1_3 = {2e 62 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "Decrypting of your files is only possible" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

