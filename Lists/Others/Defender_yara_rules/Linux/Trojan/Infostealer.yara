rule Trojan_Linux_Infostealer_DA_2147972244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Infostealer.DA!MTB"
        threat_id = "2147972244"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii //weight: 1
        $x_1_2 = "acmacodkjbdgmoleebolmdjonilkdbch" ascii //weight: 1
        $x_1_3 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii //weight: 1
        $x_1_4 = "bhhhlbepdkbapadjdnnojkbgioiodbic" ascii //weight: 1
        $x_1_5 = "mcohilncbfahbmgdjkbpemcciiolgcge" ascii //weight: 1
        $x_1_6 = "egjidjbpglichdcondbcbdnbeeppgdph" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

