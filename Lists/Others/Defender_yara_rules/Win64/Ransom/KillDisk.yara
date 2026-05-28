rule Ransom_Win64_KillDisk_SX_2147970388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/KillDisk.SX!MTB"
        threat_id = "2147970388"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "KillDisk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "90"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "JhnamStealer.dat" ascii //weight: 50
        $x_30_2 = "schtasks /delete /f /tn \"JhnamSystem" ascii //weight: 30
        $x_10_3 = "dism /online /enable-feature /featurename:NetFx3 /all /quiet /norestart" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

