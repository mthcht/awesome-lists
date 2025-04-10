rule Ransom_Win32_FrLocker_YAC_2147938530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FrLocker.YAC!MTB"
        threat_id = "2147938530"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FrLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VOTRE RESEAU A ETE PENETRE" ascii //weight: 1
        $x_1_2 = "fichiers importants ont ete CRYPTES" ascii //weight: 1
        $x_1_3 = "PERMANENTE LES FICHIERS ET" ascii //weight: 1
        $x_1_4 = "MODIFIEZ PAS LES FICHIERS CRYPTES" ascii //weight: 1
        $x_20_5 = "BgIAAACkAABSU0ExAAgAAAEAAQCdcgo95dJtPqeSc2znLeC8Kp7ciM5DJMTK" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

