rule Ransom_Win32_Radamcrypt_A_2147708186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Radamcrypt.A"
        threat_id = "2147708186"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Radamcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s%s.RDM" ascii //weight: 1
        $x_1_2 = "YOUR_FILES.url" ascii //weight: 1
        $x_1_3 = "id=%s&apt=%i&os=%s&ip=%s&bits=%s" ascii //weight: 1
        $x_1_4 = "Radamant_v1_Klitschko_number_one" ascii //weight: 1
        $x_1_5 = "process call create \"cmd.exe /c vssadmin delete shadows /all /quiet\"" ascii //weight: 1
        $x_1_6 = "URL=http://%s/ld/?id=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

