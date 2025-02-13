rule Ransom_Win32_Ikrik_A_2147720513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ikrik.A"
        threat_id = "2147720513"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ikrik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lick.real.decrypter" ascii //weight: 1
        $x_1_2 = "Kirk.real" ascii //weight: 1
        $x_1_3 = "CryptGenRandom" ascii //weight: 1
        $x_1_4 = "python" ascii //weight: 1
        $x_1_5 = "spyiboot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

