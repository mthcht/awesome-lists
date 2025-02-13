rule Trojan_Win32_Hocamal_A_2147717426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hocamal.A"
        threat_id = "2147717426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hocamal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "00111105001500" ascii //weight: 1
        $x_1_2 = "757575751377" ascii //weight: 1
        $x_1_3 = "1d1d121611112f300c33" ascii //weight: 1
        $x_1_4 = "1d1d2a19162409050d392933060935022a07" ascii //weight: 1
        $x_1_5 = "132417182a070b0337273d08073b0c2409130a3b272e1c392c612a372a" ascii //weight: 1
        $x_1_6 = "120e0715160013041d1d0c2822332e322e27351d1d16282f252e36321d1d02343333242f3517243332282e2f1d1d13342f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

