rule Ransom_Win32_Sacra_A_2147696745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sacra.A"
        threat_id = "2147696745"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sacra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crrsa@inet.ua" ascii //weight: 1
        $x_1_2 = ".b781cbb29054db12f88f08c6e161c199.rsa" ascii //weight: 1
        $x_1_3 = {eb fb 20 ed e0 20 c2 e0 f8 e5 ec 20 ea ee ec ef fc fe f2 e5 f0 e5 20 e7 e0 f8 e8 f4 f0 ee e2 e0 ed fb}  //weight: 1, accuracy: High
        $x_1_4 = {70 77 6d 00 00 00 00 00 00 00 6b 77 6d 00 00 00 00 00 00 00 63 70 70 00 00 00 00 00 00 00 6d 64 00 00 00 00 00 00 00 00 65 72 74 00 00 00 00 00 00 00 63 73 76 00 00 00 00 00 00 00 78 6d 6c 00 00 00 00 00 00 00 44 3a 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

