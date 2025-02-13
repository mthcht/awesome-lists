rule Worm_Win32_Levona_E_2147600358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Levona.E"
        threat_id = "2147600358"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Levona"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sorry, Saya lupa nih :)" ascii //weight: 1
        $x_1_2 = "17 Tahun Keatas" ascii //weight: 1
        $x_1_3 = "Nova.scr" ascii //weight: 1
        $x_1_4 = "AVP32.EXE" ascii //weight: 1
        $x_1_5 = "ZANARKAND.EXE" ascii //weight: 1
        $x_1_6 = "MAPISendMail" ascii //weight: 1
        $x_1_7 = "Renova_Emira" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

