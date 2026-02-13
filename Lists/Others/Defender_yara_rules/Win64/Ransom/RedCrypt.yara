rule Ransom_Win64_RedCrypt_AP_2147962991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/RedCrypt.AP!AMTB"
        threat_id = "2147962991"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "RedCrypt"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ooops! Your computer has been trashed by Mocha!" ascii //weight: 1
        $x_1_2 = "Any attempts to close Mocha will be detected" ascii //weight: 1
        $x_1_3 = "Mocha-x64.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

