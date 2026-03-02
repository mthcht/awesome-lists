rule Ransom_Win64_ObesityLocker_AB_2147963946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ObesityLocker.AB!MTB"
        threat_id = "2147963946"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ObesityLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Your files are encrypted!" ascii //weight: 3
        $x_3_2 = "OBESITY LOCKER" ascii //weight: 3
        $x_2_3 = "%s\\t.me_euxaodev_%d_%d.txt" ascii //weight: 2
        $x_2_4 = "%swallpaper_temp.bmp" ascii //weight: 2
        $x_2_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

