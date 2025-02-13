rule Trojan_Win32_StealerGen_DKL_2147808592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerGen.DKL!MTB"
        threat_id = "2147808592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerGen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "nCotecubujiyesoh pepevo fulayuwibuxabe temakenabub" ascii //weight: 2
        $x_2_2 = "zovugajoduricepeyosofahiwenayomu" ascii //weight: 2
        $x_2_3 = "rPehayuvivituxo ruxagawijud buzus pitunaba pigemuyot" ascii //weight: 2
        $x_2_4 = "Pufuyoramuhivih cofoxolawar hocag" ascii //weight: 2
        $x_2_5 = "gipevurocof" ascii //weight: 2
        $x_2_6 = "mecahusaxepobuyizajir" ascii //weight: 2
        $x_2_7 = "Vidizotina tufurinug warixolefulig" ascii //weight: 2
        $x_2_8 = "YONAMIKORUFENI" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_StealerGen_HNU_2147809085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealerGen.HNU!MTB"
        threat_id = "2147809085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealerGen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 f1 30 c1 20 f1 88 d8 34 ?? 88 ce 80 f6 ?? 88 d7 80 f7 ?? 88 c5}  //weight: 10, accuracy: Low
        $x_1_2 = "0@.eh_fram" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

