rule Trojan_Win32_Drov_2147896070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drov.MT!MTB"
        threat_id = "2147896070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drov"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b0 6e 6a 00 88 84 24 c8 01 00 00 8d 44 24 18 50 6a 09 8d 8c 24 c8 01 00 00 51 56 c7 84 24 d0 01 00 00 46 75 6e 46 c7 84 24 d4 01 00 00 75 6e 46 75}  //weight: 10, accuracy: High
        $x_3_2 = "GetTempPathW" ascii //weight: 3
        $x_3_3 = "PathAppendW" ascii //weight: 3
        $x_3_4 = "SHAMple.dat" ascii //weight: 3
        $x_3_5 = "Software\\SHAMple" ascii //weight: 3
        $x_3_6 = "gethostbyname" ascii //weight: 3
        $x_3_7 = "www.shample.ru" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_3_*))) or
            (all of ($x*))
        )
}

