rule Trojan_Win64_Limpid_PGLI_2147958157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Limpid.PGLI!MTB"
        threat_id = "2147958157"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Limpid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "https://zakupky-ru.website/content.rar" ascii //weight: 5
        $x_5_2 = "UnRAR.exe" ascii //weight: 5
        $x_5_3 = "Start-Process -FilePath $exe -WindowStyle Hidden" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

