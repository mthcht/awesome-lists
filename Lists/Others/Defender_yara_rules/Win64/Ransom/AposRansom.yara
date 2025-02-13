rule Ransom_Win64_AposRansom_YAA_2147933203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/AposRansom.YAA!MTB"
        threat_id = "2147933203"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "AposRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "vssadmin Delete Shadows /All /Quiet" ascii //weight: 5
        $x_5_2 = "powershell -ExecutionPolicy Bypass -File" ascii //weight: 5
        $x_2_3 = "EncryptHiddenDirectories" ascii //weight: 2
        $x_1_4 = "ChangeWallpaper" ascii //weight: 1
        $x_1_5 = "uploaded to our servers " ascii //weight: 1
        $x_1_6 = "backups and shadow copies have been corrupted" ascii //weight: 1
        $x_1_7 = "system unrecoverable" ascii //weight: 1
        $x_1_8 = "forced to publish your data online " ascii //weight: 1
        $x_1_9 = "permanently damage them" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

