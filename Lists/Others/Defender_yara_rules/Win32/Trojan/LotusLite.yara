rule Trojan_Win32_LotusLite_AB_2147962677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LotusLite.AB!MTB"
        threat_id = "2147962677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LotusLite"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "172.81.60.97" ascii //weight: 6
        $x_6_2 = "Global\\Technology360-A@P@T-Team" ascii //weight: 6
        $x_4_3 = "DataImporterMain" ascii //weight: 4
        $x_4_4 = "kugou.dll" ascii //weight: 4
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "KugouMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

