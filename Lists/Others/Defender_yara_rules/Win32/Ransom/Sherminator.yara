rule Ransom_Win32_Sherminator_YL_2147742843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sherminator.YL"
        threat_id = "2147742843"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sherminator"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Decoder.hta" ascii //weight: 1
        $x_1_2 = "sherminator.help@tutanota.com" ascii //weight: 1
        $x_1_3 = "you.help5@protonmail.com" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\delog.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

