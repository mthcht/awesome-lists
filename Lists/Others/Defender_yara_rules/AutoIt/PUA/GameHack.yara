rule PUA_AutoIt_GameHack_258148_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:AutoIt/GameHack!ibt"
        threat_id = "258148"
        type = "PUA"
        platform = "AutoIt: AutoIT scripts"
        family = "GameHack"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=pubg antirecoil" wide //weight: 1
        $x_1_2 = "#AutoIt3Wrapper_Res_ProductName=PubG AntiRecoil" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

