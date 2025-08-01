rule Trojan_Win32_Makoob_BM_2147849147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Makoob.BM!MTB"
        threat_id = "2147849147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Makoob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Inkassogebyr\\Nonnotably\\Hurlumhejets" ascii //weight: 1
        $x_1_2 = "Ggehvidestoffet\\Associatively\\Echinoderma.ini" ascii //weight: 1
        $x_1_3 = "Gorgoneion\\Aethogen\\Fullerton.Bim" ascii //weight: 1
        $x_1_4 = "Bundplacering\\Barts\\Udkrselssignalets\\Respost.Dis" ascii //weight: 1
        $x_1_5 = "Unsetting\\Bagbens.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Makoob_SPGJ_2147893088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Makoob.SPGJ!MTB"
        threat_id = "2147893088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Makoob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smrrebrdsbutikkernes.bre" wide //weight: 1
        $x_1_2 = "profittilegnelse" wide //weight: 1
        $x_1_3 = "skridrillen" wide //weight: 1
        $x_1_4 = "Rddeligst.san" wide //weight: 1
        $x_1_5 = "Zygobranchiata95" wide //weight: 1
        $x_1_6 = "Bernoulli.cru" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Makoob_NM_2147906168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Makoob.NM!MTB"
        threat_id = "2147906168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Makoob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "plankende orchid" wide //weight: 2
        $x_2_2 = "banditti scorpiid.exe" wide //weight: 2
        $x_2_3 = "filerede partshringsregelen knallerist" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Makoob_GA_2147928958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Makoob.GA!MTB"
        threat_id = "2147928958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Makoob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "efterlnsordningerne argean indflytningerne" wide //weight: 1
        $x_1_2 = "teth.exe" wide //weight: 1
        $x_1_3 = "arene asfreds deserteringens" wide //weight: 1
        $x_1_4 = "SeShutdownPrivilege" wide //weight: 1
        $x_1_5 = "\\Temp" wide //weight: 1
        $x_1_6 = "draabningerne flaaningernes nonusing" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Makoob_SAH_2147934106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Makoob.SAH!MTB"
        threat_id = "2147934106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Makoob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nacry.ini" wide //weight: 1
        $x_1_2 = "rgerrig.txt" wide //weight: 1
        $x_1_3 = "\\cocainize" wide //weight: 1
        $x_1_4 = "linielngde.pro" wide //weight: 1
        $x_1_5 = "Skrabnsespils.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Makoob_SVMP_2147935333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Makoob.SVMP!MTB"
        threat_id = "2147935333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Makoob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Bifloderne90.ini" ascii //weight: 2
        $x_2_2 = "hjemom.mun" ascii //weight: 2
        $x_2_3 = "Interpleader55.rik" ascii //weight: 2
        $x_1_4 = "dobbeltbevidstheds.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Makoob_SLVM_2147937765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Makoob.SLVM!MTB"
        threat_id = "2147937765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Makoob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cora\\Domsafsigelsernes.dll" wide //weight: 2
        $x_2_2 = "Astuteness250\\Titoists224.bra" wide //weight: 2
        $x_2_3 = "Titoists224.bra" wide //weight: 2
        $x_1_4 = "Lssene.Lou" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Makoob_GVA_2147938149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Makoob.GVA!MTB"
        threat_id = "2147938149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Makoob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uncollapsable hyaenodon" wide //weight: 1
        $x_1_2 = "parallaxes forlagsredaktren" wide //weight: 1
        $x_1_3 = "unsimpleness.exe" wide //weight: 1
        $x_3_4 = "revoke quartermasters sporogenic" wide //weight: 3
        $x_1_5 = "SeShutdownPrivilege" wide //weight: 1
        $x_1_6 = "avledygtigheds" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Makoob_SLOU_2147939186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Makoob.SLOU!MTB"
        threat_id = "2147939186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Makoob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "forttningernes trappy" wide //weight: 2
        $x_2_2 = "screeningernes reversibilitet ekviperingshandler" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Makoob_SERY_2147939384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Makoob.SERY!MTB"
        threat_id = "2147939384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Makoob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bordvinenes lovgivningernes" wide //weight: 1
        $x_1_2 = "vort skoldende convoluta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Makoob_SLYY_2147944892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Makoob.SLYY!MTB"
        threat_id = "2147944892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Makoob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "elevatortrucks" wide //weight: 2
        $x_2_2 = "syndebukkens busstoppestedets" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Makoob_SCE_2147944918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Makoob.SCE!MTB"
        threat_id = "2147944918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Makoob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vedheftninger maladive" wide //weight: 2
        $x_2_2 = "civiliser spikiest ekstranummer" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

