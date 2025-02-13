rule Trojan_WinNT_Kangkio_A_2147610931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Kangkio.A"
        threat_id = "2147610931"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Kangkio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b c7 45 ?? ec 56 64 a1 c7 45 ?? 24 01 00 00 c7 45 ?? 8b 75 08 3b 83 3d ?? ?? 01 00 05 75 12 83 3d ?? ?? 01 00 01 75}  //weight: 2, accuracy: Low
        $x_1_2 = "NtQuerySystemInformation faild!" ascii //weight: 1
        $x_1_3 = "Never be here ?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

