rule Worm_Win32_Phdet_A_2147658349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phdet.A"
        threat_id = "2147658349"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 24 0e 48 9c 05 00 6a 5a ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = "id=%s&ln=%s&cn=%s&nt=%s" ascii //weight: 1
        $x_1_3 = "LdrProc\" & VbCrLf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

