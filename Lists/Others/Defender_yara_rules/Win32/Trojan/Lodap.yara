rule Trojan_Win32_Lodap_AMTB_2147959861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lodap!AMTB"
        threat_id = "2147959861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lodap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "qcrjzsh@g" ascii //weight: 2
        $x_2_2 = "i\\VB6.OLBV" ascii //weight: 2
        $x_2_3 = "EVENT_SINK_AddRefD" ascii //weight: 2
        $x_2_4 = "vb6chs.dll." ascii //weight: 2
        $x_2_5 = "P_p/knelExi" ascii //weight: 2
        $x_2_6 = "award.exe" ascii //weight: 2
        $n_100_7 = "Uninst.exe" ascii //weight: -100
        $n_100_8 = "Uninstaller.exe" ascii //weight: -100
        $n_100_9 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

