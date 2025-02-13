rule Ransom_Win32_Tazwit_A_2147708395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tazwit.A"
        threat_id = "2147708395"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tazwit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 6c 6b 00 78 6c 73 00 78 6c 73 62 00 78 6c 73 6d 00 78 6c 73 78 00 78 6d 6c 00 78 70 73 00 7a 69 70 00 78 78 78}  //weight: 1, accuracy: High
        $x_1_2 = "FROM THE WH1TEH4TZ!" ascii //weight: 1
        $x_1_3 = "YOUR FILES BELONG TO US" ascii //weight: 1
        $x_1_4 = "Email us two encrypted files along with secret.key file" ascii //weight: 1
        $x_1_5 = "\\NEED_READ.TXT" ascii //weight: 1
        $x_1_6 = {2e 77 34 7a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

