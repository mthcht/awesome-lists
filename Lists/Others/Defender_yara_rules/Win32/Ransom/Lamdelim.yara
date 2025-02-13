rule Ransom_Win32_Lamdelim_A_2147720127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lamdelim.A"
        threat_id = "2147720127"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lamdelim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "We are demanding : 200$ (USD)" ascii //weight: 1
        $x_1_2 = "Yes, To Unlock Your PC Now, You can 2 things. You have to play us" ascii //weight: 1
        $x_1_3 = "Thanks for Buying the Passcode. Wish you could have no Virus from today," ascii //weight: 1
        $x_1_4 = "microsoftxyber@hackindex.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

