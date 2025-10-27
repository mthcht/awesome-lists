rule Trojan_Win32_StealerC_A_2147893555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerC.A!MTB"
        threat_id = "2147893555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 03 55 fc 0f b6 02 35 ?? 00 00 00 8b 4d 08 03 4d fc 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = "uBsyhbxUANniwu" ascii //weight: 1
        $x_1_3 = "DSuygac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StealerC_KAA_2147899659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerC.KAA!MTB"
        threat_id = "2147899659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4c 24 0c 30 04 31 46 3b f7 7c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StealerC_B_2147899787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerC.B!MTB"
        threat_id = "2147899787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f8 03 cf 89 4d ec 8b 4d f0 8b f7 d3 ee c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 d8 8b 45 ec 31 45 fc 81 3d ?? ?? ?? ?? e6 09 00 00 75 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StealerC_E_2147899880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerC.E!MTB"
        threat_id = "2147899880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "raxuxofohifakatasonabekuvo" ascii //weight: 1
        $x_1_2 = "fahubarocuvuvejegovimisiwu" ascii //weight: 1
        $x_1_3 = "loyusotonofasuba" ascii //weight: 1
        $x_1_4 = "jokediteroviwedarafinayog" ascii //weight: 1
        $x_1_5 = "jowuharatapiyilijadezumadayeduje" ascii //weight: 1
        $x_1_6 = "lumejasurinisomekep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StealerC_SPGA_2147899917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerC.SPGA!MTB"
        threat_id = "2147899917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zituvehaziyepilegeyehezesekemidelapuzayuzajebivironemus" wide //weight: 1
        $x_1_2 = "Sonoxibugawed=Zexoxep kuviley masi yagogutuduze sowoca rinebetawefuxi xitix" wide //weight: 1
        $x_1_3 = "wevisodomasamonacocidazegoluhocirakuduciwekunasigilamepidepiyupiwowazovopejibokewizi" wide //weight: 1
        $x_1_4 = "HawSWacupeyigocupi hifa hohovulet xekobehepireda talalecadoduri jipafol ciduwateb jirup" wide //weight: 1
        $x_1_5 = "Zowusogo mubaholoseyoh lihuhupeGYutodehip lozufaboxara nosasiv moji muj meguki muvisiforigasa cewuzirun" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StealerC_F_2147899979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerC.F!MTB"
        threat_id = "2147899979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dewazesovesapovehakucucet" ascii //weight: 1
        $x_1_2 = "buvubufurusepejelivukilakocotufe" ascii //weight: 1
        $x_1_3 = "xelaledovutihezebuyaxadecetezav" ascii //weight: 1
        $x_1_4 = "lumejasurinisomekep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StealerC_NB_2147900357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerC.NB!MTB"
        threat_id = "2147900357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 81 ec 08 04 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 fc 8b 45 08 56 57 33 f6 33 ff 3b de 89 85 f8 fb ff ff 7e 42}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StealerC_NN_2147900358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerC.NN!MTB"
        threat_id = "2147900358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 81 ec ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 c5 89 45 fc 8b 45 08 56 57 33 f6 33 ff 3b de 89 85 ?? ?? ?? ?? 7e 42 83 fb 2d 75 07 56}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StealerC_ALAA_2147900421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerC.ALAA!MTB"
        threat_id = "2147900421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 f8 f7 ff ff 8d 0c 30 e8 4e ff ff ff 30 01 83 fb 0f 75 19 57 8d 85 fc f7 ff ff 50 57 57 57 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StealerC_GXN_2147909451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerC.GXN!MTB"
        threat_id = "2147909451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 14 30 83 bc 24 ?? ?? ?? ?? 0f ?? ?? 6a 00 6a 00 57 8d 44 24 ?? 50 53}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StealerC_EC_2147923303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerC.EC!MTB"
        threat_id = "2147923303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".taggant" ascii //weight: 1
        $x_1_2 = "wallet_path" ascii //weight: 1
        $x_1_3 = "\\Monero\\wallet.keys" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\monero-project\\monero-core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StealerC_NH_2147927330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerC.NH!MTB"
        threat_id = "2147927330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\monero-project\\monero-core" ascii //weight: 2
        $x_1_2 = "Monero\\wallet.keys" ascii //weight: 1
        $x_1_3 = "webSocketDebuggerUrl" ascii //weight: 1
        $x_1_4 = "QZ9FNASQEMWIEBWOY96NY42V3RFUL1SN0NSZJ4UUIGCXXFXKW5R4YUAV7OM54" ascii //weight: 1
        $x_1_5 = "P4A7MOZP1EPLT8HL73UQJ62TN9MU37LOFMEP0ZLV5S2OOAHXJZUT937SCQTMBFW42BGH31VHS8U1ENEM2YKDM2PLPWMJF8T" ascii //weight: 1
        $x_1_6 = "CKUA7DIYXHL04C9P2XZLKXY2LTDUQK01VB1T4YE51BP7JUSUF4UC5SGPV2YOAXINRTF3KQUDS4UJH0S1ATPVZX6C5L7CA05D3CQ0PYJZKQTB87H4J6NR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StealerC_BSA_2147927533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerC.BSA!MTB"
        threat_id = "2147927533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {3d db 04 00 00 75 06 8d 8a 49 9e 00 00 81 f9 cf 0b 00 00 75 0c 89 3d 20 73 45 00 89 35 24 73 45 00 40 3d 56 0b 18 01 7c d7 89 0d 1c 9f 82 00 33 f6 81 fe 77 b7 55 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StealerC_ARR_2147956121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerC.ARR!MTB"
        threat_id = "2147956121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2e 64 61 74 61 00 00 00 ac df 03 00 00 a0 08}  //weight: 10, accuracy: High
        $x_3_2 = {74 61 00 00 7e 8f 01 00 00 10 07}  //weight: 3, accuracy: High
        $x_2_3 = {64 86 09 00 ab ea c9 68 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

