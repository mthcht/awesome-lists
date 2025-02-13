rule Trojan_Win32_RHADAMANTHYS_DB_2147919687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RHADAMANTHYS.DB!MTB"
        threat_id = "2147919687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RHADAMANTHYS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "71"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SDL_AtomicGetPtr" ascii //weight: 10
        $x_10_2 = "SDL_AtomicSetPtr" ascii //weight: 10
        $x_10_3 = "SDL_BuildAudioCVT" ascii //weight: 10
        $x_10_4 = "SDL_AudioStreamGet" ascii //weight: 10
        $x_10_5 = "SDL_AudioStreamPut" ascii //weight: 10
        $x_10_6 = "SDL_AudioStreamFlush" ascii //weight: 10
        $x_10_7 = "SDL2.dll" ascii //weight: 10
        $x_1_8 = "AlphaBlend" ascii //weight: 1
        $x_1_9 = "TransparentB" ascii //weight: 1
        $x_1_10 = "CreateFontPacka" ascii //weight: 1
        $x_1_11 = "GradientFill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RHADAMANTHYS_DC_2147920322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RHADAMANTHYS.DC!MTB"
        threat_id = "2147920322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RHADAMANTHYS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b c1 33 d0 0f af 95 24 fd ff ff 89 95 50 e0 ff ff 8b 95 50 e0 ff ff 89 95 4c e0 ff ff 8b 85 4c e0 ff ff 83 e8 01 89 85 48 e0 ff ff c7 85 4c ef ff ff 01 00 00 00 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RHADAMANTHYS_DD_2147931237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RHADAMANTHYS.DD!MTB"
        threat_id = "2147931237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RHADAMANTHYS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "avcodec-58.dll" ascii //weight: 10
        $x_1_2 = "AlphaBlend" ascii //weight: 1
        $x_1_3 = "av1_ac_quant_Q3" ascii //weight: 1
        $x_1_4 = "av1_ac_quant_QTX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

