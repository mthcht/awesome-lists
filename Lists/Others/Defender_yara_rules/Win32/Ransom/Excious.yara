rule Ransom_Win32_Excious_A_2147727347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Excious.A!bit"
        threat_id = "2147727347"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Excious"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii //weight: 3
        $x_1_2 = "%s\\%s.locky" ascii //weight: 1
        $x_1_3 = "vssadmin.exe vssadmin delete shadows / all / quiet" ascii //weight: 1
        $x_1_4 = "@WanaDecryptor@.exe" ascii //weight: 1
        $x_1_5 = "icacls . / grant Everyone : F / T / C / Q" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

