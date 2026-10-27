rule TrojanDownloader_Win64_NetLoader_C_2147981004_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/NetLoader.C!MTB"
        threat_id = "2147981004"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "NetLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "add_excl.ps1" ascii //weight: 1
        $x_1_2 = "Add-MpPreference -ExclusionPath $usersPath -Force -ErrorAction SilentlyContinue" ascii //weight: 1
        $x_1_3 = "useless_activity.log" ascii //weight: 1
        $x_1_4 = "useless_tmp" ascii //weight: 1
        $x_1_5 = "marker.txt" ascii //weight: 1
        $x_1_6 = "Eliminando artefactos, descargando el payload como" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

