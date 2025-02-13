rule Worm_Win32_Windaus_G_2147642804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Windaus.G"
        threat_id = "2147642804"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Windaus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MAIL FROM:<stynky_xp4rky3x@hotmail.com.com>" ascii //weight: 1
        $x_1_2 = "Subject:Hola santiago" ascii //weight: 1
        $x_1_3 = "C:\\sound.txt" ascii //weight: 1
        $x_1_4 = "datos.txt" ascii //weight: 1
        $x_1_5 = "helo me.somepalace.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

