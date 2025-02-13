rule Ransom_Win32_KKKryptoLocker_A_2147722804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/KKKryptoLocker.A!rsm"
        threat_id = "2147722804"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "KKKryptoLocker"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "400"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "KKKryptoLocker" wide //weight: 100
        $x_100_2 = "Ooops, spongebob is encrypting your files!" wide //weight: 100
        $x_100_3 = "SPONGEBOB RANSOMWARE 2.0" wide //weight: 100
        $x_100_4 = "C:\\Users\\Jared\\Desktop\\ransomware\\KKKryptoLocker\\KKKryptoLocker\\obj\\Debug\\KKKryptoLocker.pdb" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

