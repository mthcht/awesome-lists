rule Backdoor_MSIL_PasGen_YA_2147733889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/PasGen.YA!MTB"
        threat_id = "2147733889"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PasGen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://pastebin.com/api/api_post.php" wide //weight: 1
        $x_1_2 = "://pastebin.com/raw.php" wide //weight: 1
        $x_1_3 = "isDiving" wide //weight: 1
        $x_1_4 = "isShooting" wide //weight: 1
        $x_1_5 = "setPlayerDead" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

