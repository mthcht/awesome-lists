rule Trojan_AutoIt_GameHack_2147742103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AutoIt/GameHack!ibt"
        threat_id = "2147742103"
        type = "Trojan"
        platform = "AutoIt: AutoIT scripts"
        family = "GameHack"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=pubg antirecoil" wide //weight: 1
        $x_1_2 = "#AutoIt3Wrapper_Res_ProductName=PubG AntiRecoil" wide //weight: 1
        $x_1_3 = "PubG Recoil Control - By RecoilJohn" wide //weight: 1
        $x_1_4 = "Increase Recoil Speed After: " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

