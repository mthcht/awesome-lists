rule Ransom_Win32_ABCLocker_A_2147722801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ABCLocker.A!rsm"
        threat_id = "2147722801"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ABCLocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "500"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "\\cloudsword.pdb" ascii //weight: 100
        $x_100_2 = "AB HONESTO VIRUM BONUM NIHIL DETERRET" wide //weight: 100
        $x_100_3 = "encrypted by ABC Locker" wide //weight: 100
        $x_100_4 = "YOUR PASSWORD" wide //weight: 100
        $x_100_5 = "AFFILIATE ID" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

