rule Ransom_Win32_Dedsec_A_2147901783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dedsec.A"
        threat_id = "2147901783"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dedsec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DEDSEC RANSOMWARE" ascii //weight: 1
        $x_1_2 = "t.me/dedsecransom" ascii //weight: 1
        $x_1_3 = "\\ransom.py" ascii //weight: 1
        $x_1_4 = "YOUR FILES HAVE BEEN SUCCESSFULLY DECRYPTED" ascii //weight: 1
        $x_1_5 = "UklGRjT7DwBXQVZFZm10IBAAAAABAAEAgD4AAAB9AAACABAAZGF0YRD7DwD" ascii //weight: 1
        $x_1_6 = "encrypt_file.<locals>.<genexpr>" ascii //weight: 1
        $x_1_7 = "DECRYPTION_KEY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Dedsec_B_2147901785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dedsec.B!!Dedsec.B"
        threat_id = "2147901785"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dedsec"
        severity = "Critical"
        info = "Dedsec: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DEDSEC RANSOMWARE" ascii //weight: 1
        $x_1_2 = "t.me/dedsecransom" ascii //weight: 1
        $x_1_3 = "\\ransom.py" ascii //weight: 1
        $x_1_4 = "YOUR FILES HAVE BEEN SUCCESSFULLY DECRYPTED" ascii //weight: 1
        $x_1_5 = "UklGRjT7DwBXQVZFZm10IBAAAAABAAEAgD4AAAB9AAACABAAZGF0YRD7DwD" ascii //weight: 1
        $x_1_6 = "encrypt_file.<locals>.<genexpr>" ascii //weight: 1
        $x_1_7 = "DECRYPTION_KEY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

