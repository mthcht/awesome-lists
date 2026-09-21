rule Trojan_Win64_GrayRabbitLoader_A_2147978542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GrayRabbitLoader.A!AMTB"
        threat_id = "2147978542"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GrayRabbitLoader"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "boy.dll" ascii //weight: 3
        $x_2_2 = ":\\Windows\\iexplore.exe" ascii //weight: 2
        $x_2_3 = "c:\\users\\public\\" ascii //weight: 2
        $x_1_4 = "7z.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

