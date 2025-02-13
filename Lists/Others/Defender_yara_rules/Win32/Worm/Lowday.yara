rule Worm_Win32_Lowday_A_2147624801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Lowday.A"
        threat_id = "2147624801"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Lowday"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ProgramKecil\\SetanWare\\LWDay.2\\LWDay.vbp" wide //weight: 10
        $x_1_2 = "Run\\windll" wide //weight: 1
        $x_1_3 = "[AutoRun]" wide //weight: 1
        $x_1_4 = "OPEN=cerita cinta DAGO4.doc  .exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

