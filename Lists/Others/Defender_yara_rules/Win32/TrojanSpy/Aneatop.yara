rule TrojanSpy_Win32_Aneatop_A_2147696151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Aneatop.A"
        threat_id = "2147696151"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Aneatop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "60F822CA69D4022EA54ACD7FD070E86595B864F61AD07A8BCE72AE41C66AE86F8ECA7797B415BB12B866819A26C04E" wide //weight: 1
        $x_1_2 = "B8AD5993AE" wide //weight: 1
        $x_1_3 = "6DD07EA658" wide //weight: 1
        $x_1_4 = "1F21283C" wide //weight: 1
        $x_1_5 = "7B83A648EC68EF055D99E360F76DE56D90B660" wide //weight: 1
        $x_1_6 = "KJBV44Z6HZH2379ACI6TSEU44" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

