rule Worm_Win32_Hupid_A_2147593224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hupid.A"
        threat_id = "2147593224"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E:\\Coba Software\\Virus\\BRR\\MOTTO_BRR.vbp" wide //weight: 1
        $x_1_2 = "MrHelloween.scr" wide //weight: 1
        $x_1_3 = "PersistMoniker=file://BRR\\Folder.htt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

