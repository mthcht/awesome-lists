rule Ransom_Win32_Vaultcrypt_A_2147710791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Vaultcrypt.A"
        threat_id = "2147710791"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Vaultcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sub Window_Onload" ascii //weight: 1
        $x_1_2 = " VAULT.KEY<br>" ascii //weight: 1
        $x_1_3 = "01FNSH-%d" ascii //weight: 1
        $x_1_4 = "FHASH-%d" ascii //weight: 1
        $x_1_5 = "-----BEGIN PUBLIC KEY-----" ascii //weight: 1
        $x_1_6 = "=\"http://dist.torproject.org/torbrowser" ascii //weight: 1
        $x_1_7 = "=\"http://torscreen.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Vaultcrypt_A_2147714361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Vaultcrypt.A!!Vaultcrypt.gen!A"
        threat_id = "2147714361"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Vaultcrypt"
        severity = "Critical"
        info = "Vaultcrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sub Window_Onload" ascii //weight: 1
        $x_1_2 = {2e 76 61 75 6c 74 00}  //weight: 1, accuracy: High
        $x_1_3 = ".xls|.doc|.rtf" ascii //weight: 1
        $x_1_4 = "|program|avatar|" ascii //weight: 1
        $x_1_5 = "01FNSH-%d" ascii //weight: 1
        $x_1_6 = "FHASH-%d" ascii //weight: 1
        $x_1_7 = "=\"http://torscreen.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

