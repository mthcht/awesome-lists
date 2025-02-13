rule Worm_Win32_Morbuk_A_2147636404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Morbuk.A"
        threat_id = "2147636404"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Morbuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 04 37 3c 3a 88 04 1f 74 0d 47 89 34 24}  //weight: 2, accuracy: High
        $x_2_2 = {0f be ca 83 38 01 74 b2 89 0c 24 b8 03 01 00 00 89 44 24 04}  //weight: 2, accuracy: High
        $x_2_3 = {83 ec 04 83 f8 02 75 ?? 89 34 24 fe c3 e8 ?? ?? ?? ?? 80 fb 5a 7e c7}  //weight: 2, accuracy: Low
        $x_1_4 = "[AutoRun]" ascii //weight: 1
        $x_1_5 = ";shell\\explore=Manager(&X)" ascii //weight: 1
        $x_1_6 = ".php?comp=%s&msg=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

