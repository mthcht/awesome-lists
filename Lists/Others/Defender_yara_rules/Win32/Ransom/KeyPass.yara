rule Ransom_Win32_Keypass_A_2147741523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Keypass.A"
        threat_id = "2147741523"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Keypass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "alnumalphablankcntrldigitgraphlowerprintpunctspaceunicodeuppervwordxdigit" wide //weight: 1
        $x_1_2 = "\\x{2028}\\x{2029}])" wide //weight: 1
        $x_1_3 = "\\Doc\\My work (C++)\\_New 2018\\Encryption\\Release\\encrypt.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

