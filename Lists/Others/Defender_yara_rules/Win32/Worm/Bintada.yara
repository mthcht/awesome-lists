rule Worm_Win32_Bintada_A_2147706047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bintada.A"
        threat_id = "2147706047"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bintada"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Memoria insertada ..." wide //weight: 1
        $x_1_2 = {5b 41 75 74 6f 52 75 6e 5d 06 12 6f 70 65 6e 3d 50 72 6f 6d 6f}  //weight: 1, accuracy: High
        $x_1_3 = "reproducirVideoTimer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

