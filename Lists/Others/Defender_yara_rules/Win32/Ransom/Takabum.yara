rule Ransom_Win32_Takabum_A_2147710299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Takabum.A"
        threat_id = "2147710299"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Takabum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $n_1_1 = "\\Bin\\a2hooks32.pdb" ascii //weight: -1
        $n_1_2 = "\\{A2IPC}" ascii //weight: -1
        $n_1_3 = "[a2hooks]" ascii //weight: -1
        $n_1_4 = "CicLoaderWndClass" ascii //weight: -1
        $n_1_5 = "Testing key \"%s\" value \"%s\"" ascii //weight: -1
        $n_1_6 = "name = %p - namelen = %d" ascii //weight: -1
        $x_1_7 = {5c 68 69 73 74 6f 72 79 5c [0-32] 5c 6d 6f 7a 69 6c 6c 61 5c [0-32] 5c 63 68 72 6f 6d 65 5c [0-32] 5c 74 65 6d 70 5c}  //weight: 1, accuracy: Low
        $x_1_8 = "jfif,jpe,jpeg,jpg,js,kdb,kdc,kf,layout," ascii //weight: 1
        $x_1_9 = "other important files have been encrypted with strongest encryption and unique key" ascii //weight: 1
        $x_2_10 = {44 45 43 52 59 50 54 5f 49 4e 46 4f 5f [0-16] 2e 68 74 6d 6c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

