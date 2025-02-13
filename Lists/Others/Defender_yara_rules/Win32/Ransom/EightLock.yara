rule Ransom_Win32_EightLock_A_2147712462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/EightLock.A"
        threat_id = "2147712462"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "EightLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".8lock8" wide //weight: 2
        $x_1_2 = "*.docx" wide //weight: 1
        $x_2_3 = "\\READ_IT.txt" wide //weight: 2
        $x_4_4 = "c:\\Users\\ss\\Desktop\\ihate11\\ihate11\\obj\\Release\\ihate11.pdb" ascii //weight: 4
        $x_5_5 = "contact by e-mail: d1d81238@tuta.io  or d1d81238@india.com " wide //weight: 5
        $x_4_6 = "http://5.1.83.182:8000/cgi-bin/hello.py?" wide //weight: 4
        $x_2_7 = "to identify , use lower hash!" wide //weight: 2
        $x_1_8 = "CryptoStreamMode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

