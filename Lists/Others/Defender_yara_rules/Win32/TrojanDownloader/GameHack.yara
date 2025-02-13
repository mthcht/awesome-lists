rule TrojanDownloader_Win32_GameHack_ABB_2147907646_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/GameHack.ABB!MTB"
        threat_id = "2147907646"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "GameHack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://bruh.games/internal/sru/SRU_Internal_Loader.exe" ascii //weight: 1
        $x_1_2 = "http://bruh.games/internal/sru/SRU_Internal.dll" ascii //weight: 1
        $x_1_3 = "SRU_Internal_Loader.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

