rule Trojan_Win32_Pterodactyl_CB_2147839185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodactyl.CB!MTB"
        threat_id = "2147839185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodactyl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rootoo.dll" ascii //weight: 1
        $x_1_2 = "SctvygFcgh" ascii //weight: 1
        $x_1_3 = "RfvbhSfcvbh" ascii //weight: 1
        $x_1_4 = "SfvgJuim" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pterodactyl_SPQ_2147841206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodactyl.SPQ!MTB"
        threat_id = "2147841206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodactyl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RcdfvgOjmnh" ascii //weight: 1
        $x_1_2 = "WcefMnybr" ascii //weight: 1
        $x_1_3 = "XrctvybKnubyv" ascii //weight: 1
        $x_1_4 = "tfuyukty.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pterodactyl_SPL_2147842162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pterodactyl.SPL!MTB"
        threat_id = "2147842162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pterodactyl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FerfyGdrgf" ascii //weight: 1
        $x_1_2 = "AdfghOthgrd" ascii //weight: 1
        $x_1_3 = "KyjthrgJyfjt" ascii //weight: 1
        $x_1_4 = "rdrufnitu.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

