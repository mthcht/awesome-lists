rule Ransom_Win32_Cylance_AMTB_2147974185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cylance!AMTB"
        threat_id = "2147974185"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cylance"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Global\\FSWiper" ascii //weight: 1
        $x_1_2 = "yamag@onionmail" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\a7k9p2q.dll" ascii //weight: 1
        $x_1_4 = "a7k9p2q Ransomware" ascii //weight: 1
        $x_1_5 = "a7k9p2q-ReadMe.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

