rule Ransom_Win32_Netwalker_GM_2147756665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Netwalker.GM!MTB"
        threat_id = "2147756665"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwalker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Netwalker Decrypter" ascii //weight: 2
        $x_2_2 = "Delete crypter *.txt files" ascii //weight: 2
        $x_5_3 = "netwalker" ascii //weight: 5
        $x_5_4 = "Browse folder or disk" ascii //weight: 5
        $x_2_5 = "Delete crypter note files" ascii //weight: 2
        $x_5_6 = "expand 32-byte kexpand 16-byte k" ascii //weight: 5
        $x_5_7 = "File decrypted" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

