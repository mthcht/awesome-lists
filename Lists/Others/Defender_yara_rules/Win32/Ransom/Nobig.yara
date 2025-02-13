rule Ransom_Win32_Nobig_2147724424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nobig"
        threat_id = "2147724424"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nobig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "To restore the files, wrote to the email:bomboms123@mail.ru" ascii //weight: 5
        $x_5_2 = "if you do not receive a response from this mail within 24 hours then write to  the subsidiary:yourfood20@mail.ru" ascii //weight: 5
        $x_5_3 = "echo del elevator.exe >> dls.bat" wide //weight: 5
        $x_5_4 = "5.8.88.237" ascii //weight: 5
        $x_5_5 = "User-Agent: GIBON" ascii //weight: 5
        $x_5_6 = "FIND GIBON BUFFER SIZE" ascii //weight: 5
        $x_5_7 = "FIND GIBON SUPERADMIN MESSAGE" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

