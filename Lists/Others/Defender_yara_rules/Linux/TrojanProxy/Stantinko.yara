rule TrojanProxy_Linux_Stantinko_A_2147769251_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Linux/Stantinko.A!MTB"
        threat_id = "2147769251"
        type = "TrojanProxy"
        platform = "Linux: Linux platform"
        family = "Stantinko"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "proxy_ip=" ascii //weight: 1
        $x_2_2 = "/kbdmai/DRTIPROV/index.php" ascii //weight: 2
        $x_2_3 = "/kbdmai/winsvc/index.php" ascii //weight: 2
        $x_4_4 = {48 8b 45 f8 be ?? ?? ?? ?? 48 89 c7 e8 ?? ?? ?? ?? 48 85 c0 74 1f 48 8b 45 f8 be ?? ?? ?? ?? 48 89 c7 e8 ?? ?? ?? ?? 48 85 c0 74 09 48 8b 05 ?? ?? ?? ?? eb 55}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

