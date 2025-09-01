rule Trojan_MSIL_ClipBanker_CB_2147745163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.CB!MTB"
        threat_id = "2147745163"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AdobeConfig.txt" wide //weight: 1
        $x_1_2 = "vanityAddresses" wide //weight: 1
        $x_1_3 = "AdobeUpdate.Properties.Resources" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_GA_2147748138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GA!MTB"
        threat_id = "2147748138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 42 69 74 63 6f 69 6e 2d 47 72 61 62 62 65 72 2d 6d 61 73 74 65 72 5c 42 69 74 63 6f 69 6e 2d 47 72 61 62 62 65 72 5c [0-50] 2e 70 64 62}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_GA_2147748138_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GA!MTB"
        threat_id = "2147748138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Clipboard" ascii //weight: 10
        $x_10_2 = "AddClipboardFormatListener" ascii //weight: 10
        $x_1_3 = "WM_CLIPBOARDUPDATE" ascii //weight: 1
        $x_1_4 = "currentClipboard" ascii //weight: 1
        $x_1_5 = "Regex" ascii //weight: 1
        $x_1_6 = "ethereum" ascii //weight: 1
        $x_1_7 = "ApartmentState" ascii //weight: 1
        $x_1_8 = "(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,35}" ascii //weight: 1
        $x_1_9 = "b0x[a-fA-F0-9]{40}" ascii //weight: 1
        $x_1_10 = "b4([0-9]|[A-B])(.){93}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_GB_2147753783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GB!MTB"
        threat_id = "2147753783"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Clipper" ascii //weight: 10
        $x_1_2 = "Clipboard" ascii //weight: 1
        $x_1_3 = "schtasks.exe" ascii //weight: 1
        $x_1_4 = "ymoney" ascii //weight: 1
        $x_1_5 = "payeer" ascii //weight: 1
        $x_1_6 = "bitcoin" ascii //weight: 1
        $x_1_7 = "ripple" ascii //weight: 1
        $x_1_8 = "etherium" ascii //weight: 1
        $x_1_9 = "monero" ascii //weight: 1
        $x_1_10 = "LiteCoin" ascii //weight: 1
        $x_1_11 = "steamcommunity.com/tradeoffer" ascii //weight: 1
        $x_1_12 = "donationalerts.com/" ascii //weight: 1
        $n_10_13 = "sounder" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_A_2147765585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.A!MTB"
        threat_id = "2147765585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 02 07 6f 40 00 00 0a 03 07 03 6f 48 00 00 0a 5d 6f 40 00 00 0a 61 d1 6f 49 00 00 0a 26 07 17 58 0b 07 02 6f 48 00 00 0a 32 d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AB_2147770041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AB!MTB"
        threat_id = "2147770041"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {40 01 57 d4 02 fc c9 02}  //weight: 5, accuracy: High
        $x_10_2 = {fa 25 33 00 16 00 00 02 00 00 00 2c 00 00 00 0b 00 00 00 2b}  //weight: 10, accuracy: High
        $x_5_3 = {76 34 2e 30 2e 33 30 33 31 39 00 00 00 00 00 00 00 00 09}  //weight: 5, accuracy: High
        $x_3_4 = "AssemblyTrademarkAttribute" ascii //weight: 3
        $x_3_5 = "get_CurrentDomain" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_AB_2147770041_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AB!MTB"
        threat_id = "2147770041"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {40 01 57 d4 02 fc c9 02}  //weight: 5, accuracy: High
        $x_10_2 = {fa 25 33 00 16 00 00 02 00 00 00 2d 00 00 00 0b 00 00 00 2b 00 00 00 39 00 00 00 3b 00 00 00 0f 00 00 00 01 00 00 00 01 00 00 00 11}  //weight: 10, accuracy: High
        $x_5_3 = {76 34 2e 30 2e 33 30 33 31 39 00 00 00 00 00 00 00 00 09}  //weight: 5, accuracy: High
        $x_3_4 = "AssemblyTrademarkAttribute" ascii //weight: 3
        $x_3_5 = "get_CurrentDomain" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_GC_2147774355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GC!MTB"
        threat_id = "2147774355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Clipper" ascii //weight: 10
        $x_1_2 = "Clipboard" ascii //weight: 1
        $x_1_3 = "Regex" ascii //weight: 1
        $x_1_4 = "choice /C Y /N /D Y /T" ascii //weight: 1
        $x_1_5 = "schtasks" ascii //weight: 1
        $x_1_6 = "0x[a-fA-F0-9]{40}" ascii //weight: 1
        $x_1_7 = "APPDATA" ascii //weight: 1
        $x_1_8 = "processhacker" ascii //weight: 1
        $x_1_9 = "procexp" ascii //weight: 1
        $x_1_10 = "taskmgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_GC_2147774355_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GC!MTB"
        threat_id = "2147774355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "steamcommunity.com/tradeoffer" ascii //weight: 10
        $x_1_2 = "Clipboard" ascii //weight: 1
        $x_1_3 = "WM_DRAWCLIPBOARD" ascii //weight: 1
        $x_1_4 = "SetClipboardViewer" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "ApartmentState" ascii //weight: 1
        $x_1_7 = "vmwaretray" ascii //weight: 1
        $x_1_8 = "vboxservice" ascii //weight: 1
        $x_1_9 = "vmtoolsd" ascii //weight: 1
        $x_1_10 = "SbieDll.dll" ascii //weight: 1
        $x_1_11 = "XGIocXxwKVthLXowLTldezQxfVxi" ascii //weight: 1
        $x_1_12 = "XGIweFthLWZBLUYwLTldezQwfVxi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_GD_2147775633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GD!MTB"
        threat_id = "2147775633"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Clipboard" ascii //weight: 1
        $x_1_2 = "Regex" ascii //weight: 1
        $x_1_3 = "Clipper" ascii //weight: 1
        $x_1_4 = "zcash" ascii //weight: 1
        $x_1_5 = "bitcoincash" ascii //weight: 1
        $x_1_6 = "(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,35}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_GD_2147775633_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GD!MTB"
        threat_id = "2147775633"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,35}" ascii //weight: 1
        $x_1_3 = "Regex" ascii //weight: 1
        $x_1_4 = "Clipper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ACF_2147779933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ACF!MTB"
        threat_id = "2147779933"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "yourBTCAddress" ascii //weight: 5
        $x_5_2 = "StartGrabbing" ascii //weight: 5
        $x_5_3 = "Miner" ascii //weight: 5
        $x_5_4 = "PromptOnSecureDesktop" ascii //weight: 5
        $x_5_5 = "ConsentPromptBehaviorAdmin" ascii //weight: 5
        $x_4_6 = "(WindowsRuntimeBroker)" ascii //weight: 4
        $x_4_7 = "payloadBuffer" ascii //weight: 4
        $x_4_8 = "Add-MpPreference -ExclusionPath" ascii //weight: 4
        $x_4_9 = "Set-MpPreference -PUAProtection" ascii //weight: 4
        $x_4_10 = "DisableNotifications" ascii //weight: 4
        $x_4_11 = "DetectVirtualMachine" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_4_*))) or
            ((1 of ($x_5_*) and 5 of ($x_4_*))) or
            ((2 of ($x_5_*) and 4 of ($x_4_*))) or
            ((3 of ($x_5_*) and 3 of ($x_4_*))) or
            ((4 of ($x_5_*) and 1 of ($x_4_*))) or
            ((5 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_GF_2147780460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GF!MTB"
        threat_id = "2147780460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Clipboard" ascii //weight: 1
        $x_1_2 = "BTC Stealer" ascii //weight: 1
        $x_1_3 = "^[13][a-km-zA-HJ-NP-Z0-9]{26,33}$" ascii //weight: 1
        $x_1_4 = "BitCoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_GF_2147780460_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GF!MTB"
        threat_id = "2147780460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Clipper" ascii //weight: 10
        $x_1_2 = "Clipboard" ascii //weight: 1
        $x_1_3 = "Regex" ascii //weight: 1
        $x_1_4 = "AddClipboardFormatListener" ascii //weight: 1
        $x_1_5 = "@echo off" ascii //weight: 1
        $x_1_6 = "START \"\"" ascii //weight: 1
        $x_1_7 = "Legendhot Team" ascii //weight: 1
        $x_1_8 = "^bc1[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz].*$" ascii //weight: 1
        $x_1_9 = "^0x[a-fA-F0-9]{40}$" ascii //weight: 1
        $x_1_10 = "^(q|p)[a-z0-9]{41}$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_GF_2147780460_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GF!MTB"
        threat_id = "2147780460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kq6yKSPpnqMzy4z2CZQ" ascii //weight: 1
        $x_1_2 = "DownloadString" ascii //weight: 1
        $x_1_3 = "HBWaQFTgPMkhNgTTgbf" ascii //weight: 1
        $x_1_4 = "a5PrRCgHDI8BcKGd8Si" ascii //weight: 1
        $x_1_5 = "ToString" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "GetString" ascii //weight: 1
        $x_1_9 = "CreateDecryptor" ascii //weight: 1
        $x_1_10 = "https://api.telegram.org/bot" ascii //weight: 1
        $x_1_11 = "https://ipv4bot.whatismyipaddress.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_DA_2147781176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.DA!MTB"
        threat_id = "2147781176"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 01 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 16 8c 14 00 00 01 14 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 2a}  //weight: 5, accuracy: Low
        $x_5_2 = {72 b6 fa 01 70 72 ba fa 01 70 6f ?? ?? ?? 0a 72 be fa 01 70 72 c2 fa 01 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 80 01 00 00 04 2a}  //weight: 5, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Convert" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "ConsoleApp1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_MR_2147781259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.MR!MTB"
        threat_id = "2147781259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1f 3a 5a 11 06 58 13 08 07 11 07 11 08 20 ff ?? ?? ?? 5f d2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_MR_2147781259_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.MR!MTB"
        threat_id = "2147781259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$fe203f74-fe79-4d71-8ecb-268f3d87bc98" ascii //weight: 1
        $x_1_2 = "WinHost.exe" ascii //weight: 1
        $x_1_3 = "Sevirem.Clipper" ascii //weight: 1
        $x_1_4 = "Decrypt" ascii //weight: 1
        $x_1_5 = "GCHandle" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "RuntimeFieldHandle" ascii //weight: 1
        $x_1_8 = "BitDecoder" ascii //weight: 1
        $x_1_9 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_PA_2147783594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.PA!MTB"
        threat_id = "2147783594"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Invoke" ascii //weight: 1
        $x_1_2 = "Decryp" ascii //weight: 1
        $x_1_3 = "Resolve" ascii //weight: 1
        $x_1_4 = "Encoding" ascii //weight: 1
        $x_1_5 = "Decompress" ascii //weight: 1
        $x_1_6 = "LzmaDecoder" ascii //weight: 1
        $x_1_7 = "LoadModule" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "$417450af-ed6d-4177-b0cb-cef4ccdbdb02" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_V_2147783949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.V!MTB"
        threat_id = "2147783949"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ethereum" ascii //weight: 1
        $x_1_2 = "Bitcoin" ascii //weight: 1
        $x_1_3 = "cryptocurrency" ascii //weight: 1
        $x_1_4 = "Clipp" ascii //weight: 1
        $x_1_5 = "0x164c6670b90375Fc5eF025F0EFa664513D9d1489" ascii //weight: 1
        $x_1_6 = "%5cb(bc1%7c%5b13%5d)%5ba-zA-HJ-NP-Z0-9%5d%7b26%2c35%7d%5cb" ascii //weight: 1
        $x_1_7 = "%5cb0x%5ba-fA-F0-9%5d%7b40%7d%5cb" ascii //weight: 1
        $x_1_8 = "WM_CLIPBOARDUPDATE" ascii //weight: 1
        $x_1_9 = "AddClipboardFormatListener" ascii //weight: 1
        $x_1_10 = "URLDecode" ascii //weight: 1
        $x_1_11 = "Sys32Hotfix" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_VI_2147783950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.VI!MTB"
        threat_id = "2147783950"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vmwaretray" ascii //weight: 1
        $x_1_2 = "SbieCtrl" ascii //weight: 1
        $x_1_3 = "OnClipboardChange" ascii //weight: 1
        $x_1_4 = "SetClipboardViewer" ascii //weight: 1
        $x_1_5 = "MIICXQIBAAKBgQDb" ascii //weight: 1
        $x_1_6 = "gYAfxOwwi" ascii //weight: 1
        $x_1_7 = "nBrdThuWhtDHQNg" ascii //weight: 1
        $x_1_8 = "WgIBAAKBgH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_DB_2147786210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.DB!MTB"
        threat_id = "2147786210"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SystemSocketTasks" ascii //weight: 1
        $x_1_2 = "asdasfsa" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "IsLogging" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_DC_2147786211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.DC!MTB"
        threat_id = "2147786211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OIADNAIS3q" ascii //weight: 1
        $x_1_2 = "SystemString" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "CreateInstance" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "IsLogging" ascii //weight: 1
        $x_1_7 = "get_IsAlive" ascii //weight: 1
        $x_1_8 = "Convert" ascii //weight: 1
        $x_1_9 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AV_2147786314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AV!MTB"
        threat_id = "2147786314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {08 16 06 6f 37 00 00 0a 6f 29 00 00 0a 13 05 06 11 05 6f 38 00 00 0a 13 06 07 11 06 6f 39 00 00 0a 26 00 11 04 17 58 13 04 11 04 02 fe 02 16 fe 01 13 07 11 07 2d c8}  //weight: 10, accuracy: High
        $x_3_2 = "CheckIfInfected" ascii //weight: 3
        $x_3_3 = "Payload" ascii //weight: 3
        $x_3_4 = "LimeUSBModule" ascii //weight: 3
        $x_3_5 = "infectedFile" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_VE_2147789434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.VE!MTB"
        threat_id = "2147789434"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bvsdvdssd" ascii //weight: 1
        $x_1_2 = "4LIFEBUOY_LIFEGUARD_LIFESAVER_SAFETY_RING_ICON_191552" wide //weight: 1
        $x_1_3 = "hfghggfgd" wide //weight: 1
        $x_1_4 = "AC50D15034" ascii //weight: 1
        $x_1_5 = "Non Obfuscated" ascii //weight: 1
        $x_1_6 = "mSVfgNjUYRlMlZQiKaecifBaFEzfBA9z1zVH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ABM_2147789556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ABM!MTB"
        threat_id = "2147789556"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Stealer" ascii //weight: 3
        $x_3_2 = "KeyValuePair" ascii //weight: 3
        $x_3_3 = "X509Chain" ascii //weight: 3
        $x_3_4 = "RegexPatterns" ascii //weight: 3
        $x_3_5 = "ClipboardMonitor" ascii //weight: 3
        $x_3_6 = "clipboard_changed" ascii //weight: 3
        $x_3_7 = "replace_clipboard" ascii //weight: 3
        $x_3_8 = "Autorun" ascii //weight: 3
        $x_3_9 = "is_installed" ascii //weight: 3
        $x_3_10 = "clipboard_check_delay" ascii //weight: 3
        $x_3_11 = "set_hidden" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_JJ_2147793429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.JJ!MTB"
        threat_id = "2147793429"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ydisk" ascii //weight: 1
        $x_1_2 = "steam" ascii //weight: 1
        $x_1_3 = "monero" ascii //weight: 1
        $x_1_4 = "bitcoin" ascii //weight: 1
        $x_1_5 = "autorun" ascii //weight: 1
        $x_1_6 = "ProcessStartInfo" ascii //weight: 1
        $x_1_7 = "DirectoryInfo" ascii //weight: 1
        $x_1_8 = "payeer" ascii //weight: 1
        $x_1_9 = "ymoney" ascii //weight: 1
        $x_1_10 = "steamcommunity.com/tradeoffer/new" wide //weight: 1
        $x_1_11 = "qiwi.me" wide //weight: 1
        $x_1_12 = "donationalerts.com/r" wide //weight: 1
        $x_1_13 = "yadi.sk/d" wide //weight: 1
        $x_1_14 = "DALERTS" wide //weight: 1
        $x_1_15 = "RIPPLE" wide //weight: 1
        $x_1_16 = "LiteCoin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_VW_2147793666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.VW!MTB"
        threat_id = "2147793666"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SysHostt" ascii //weight: 1
        $x_1_2 = "Decompress" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "BitDecoder" ascii //weight: 1
        $x_1_5 = "ReverseDecode" ascii //weight: 1
        $x_1_6 = "LzmaDecoder" ascii //weight: 1
        $x_1_7 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_8 = "LoadModule" ascii //weight: 1
        $x_1_9 = "BlockCopy" ascii //weight: 1
        $x_1_10 = "ToBase64String" ascii //weight: 1
        $x_1_11 = "GetEntryAssembly" ascii //weight: 1
        $x_1_12 = "MemoryStream" ascii //weight: 1
        $x_1_13 = "ReadByte" ascii //weight: 1
        $x_10_14 = {11 17 20 8f a0 12 fb 5a 20 29 3c 1e 84 61}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_DY_2147794428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.DY!MTB"
        threat_id = "2147794428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MARKETING_SEO_ADVERTISING_PROMOTION_ICON_192432" wide //weight: 1
        $x_1_2 = "0k000h222]776K" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "adfasdas" ascii //weight: 1
        $x_1_5 = "ResolveSignature" ascii //weight: 1
        $x_1_6 = "get_FullName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_DY_2147794428_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.DY!MTB"
        threat_id = "2147794428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "adfasdas" ascii //weight: 1
        $x_1_2 = "afdgdfsfs" ascii //weight: 1
        $x_1_3 = "ResolveSignature" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "m_DictionarySizeCheck" ascii //weight: 1
        $x_1_6 = "ADD_TO_CART_ONLINE_SHOPPING_ICON_192425" wide //weight: 1
        $x_1_7 = "gfddsfdsf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_Z_2147794627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.Z!MTB"
        threat_id = "2147794627"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YnRuUmVmcmVzaFNoYXJpbmdz" ascii //weight: 1
        $x_1_2 = "6Jma5ouf6Lev55Sx5Yqp5omL" ascii //weight: 1
        $x_1_3 = "U3RvcFRvb2xTdHJpcE1lbnVJdGVt" ascii //weight: 1
        $x_1_4 = "bnVtTWF4Q2xpZW50cw== 5a6i5oi356uv5YiX6KGo77yIezB977yJ 5a6i5oi356uv5YiX6KGo77yIMO+8iQ==" ascii //weight: 1
        $x_1_5 = "dHh0UGF0aA==,U3RvcFNoYXJpbmdBbGxUb29sU3RyaXBNZW51SXRlbQ==" ascii //weight: 1
        $x_1_6 = "5omT5byA(U3RvcFNoYXJpbmdUb29sU3RyaXBNZW51SXRlbQ==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_G_2147795126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.G!MTB"
        threat_id = "2147795126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wQQSxJfdL.bin" wide //weight: 1
        $x_1_2 = "aSILlzCwXBSrQ" wide //weight: 1
        $x_1_3 = "http://mensajay.com/getSemesters.php" wide //weight: 1
        $x_1_4 = "add_Shutdown" ascii //weight: 1
        $x_1_5 = "Doc52" ascii //weight: 1
        $x_1_6 = "Windows16" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_GE_2147795258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GE!MTB"
        threat_id = "2147795258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Clipper" ascii //weight: 10
        $x_1_2 = "Clipboard" ascii //weight: 1
        $x_1_3 = "Regex" ascii //weight: 1
        $x_1_4 = "Banker" ascii //weight: 1
        $x_1_5 = "Bitcoin" ascii //weight: 1
        $x_1_6 = "Ripple" ascii //weight: 1
        $x_1_7 = "Payeer" ascii //weight: 1
        $x_1_8 = "Zcash" ascii //weight: 1
        $x_1_9 = "schtasks" ascii //weight: 1
        $x_1_10 = "SELECT * FROM Win32_ComputerSystem" ascii //weight: 1
        $x_1_11 = "vmware" ascii //weight: 1
        $x_1_12 = "AntiVm" ascii //weight: 1
        $x_1_13 = "IPLogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_QA_2147795398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.QA!MTB"
        threat_id = "2147795398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fa 25 33 00 16 00 00 02 00 00 00 46 00 00 00 17 00 00 00 58 00 00 00 91 00 00 00 60 00 00 00 11 00 00 00 01 00 00 00 03 00 00 00 1a 00 00 00 01 00 00 00 03 00 00 00 01 00 00 00 03 00 00 00 0a 00 00 00 09 00 00 00 02 00 00 00 02 00 00 00 01}  //weight: 10, accuracy: High
        $x_3_2 = "add_AssemblyResolve" ascii //weight: 3
        $x_3_3 = "get_IsAlive" ascii //weight: 3
        $x_3_4 = "Confuser.Core 1.5.0" ascii //weight: 3
        $x_3_5 = "FailFast" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_DF_2147795869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.DF!MTB"
        threat_id = "2147795869"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovL3FqcXBxaWFtaDIuZXRlcm5hbGhvc3QuaW5mby8=" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
        $x_1_3 = "SELECT * FROM AntiVirusProduct" ascii //weight: 1
        $x_1_4 = "RemoteDebuggerPresent" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_PEI_2147795871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.PEI!MTB"
        threat_id = "2147795871"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 23 00 56 00 71 00 51 00 40 00 40 00 4d 00 40}  //weight: 1, accuracy: High
        $x_1_2 = "4fug4@t@nNIbgB#M0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4g" wide //weight: 1
        $x_1_3 = "c3Y#VjN#YxO#M0Z#@4OSN#eX" wide //weight: 1
        $x_1_4 = "loimensaturn.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_IFK_2147797051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.IFK!MTB"
        threat_id = "2147797051"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wYttUKzFCpYhTfqHwRcLvLgkJUJeA1" ascii //weight: 1
        $x_1_2 = "YaYpxmWuhdNusgTiyVgsKNSVzxij" ascii //weight: 1
        $x_1_3 = "ftSJZJerEmLUwXGpfBiEFqbkfhmi9" ascii //weight: 1
        $x_1_4 = "ZplCWrUZQIVmUdcbNzjLIpVBdLKDJ" ascii //weight: 1
        $x_1_5 = "cnCkUeNpLVRPoBAoAHdTCjoDYkJz" ascii //weight: 1
        $x_1_6 = "jkaeido30.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_IFK_2147797051_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.IFK!MTB"
        threat_id = "2147797051"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OUTPUT-ONLINEPNGTOOLS" wide //weight: 1
        $x_1_2 = "ufaiofwq.exe" wide //weight: 1
        $x_1_3 = "Discord Link :  v1.0.0-custom" ascii //weight: 1
        $x_1_4 = "ShellExecute" ascii //weight: 1
        $x_1_5 = "get_CurrentDomain" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "set_UserAgent" ascii //weight: 1
        $x_1_8 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_XS_2147797901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.XS!MTB"
        threat_id = "2147797901"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bitcoinminingsoftware.Bitcoin_Grabber" ascii //weight: 1
        $x_1_2 = "ClipboardNotification" ascii //weight: 1
        $x_1_3 = "bitcoinminingsoftware.pdb" ascii //weight: 1
        $x_1_4 = "your_Btc" ascii //weight: 1
        $x_1_5 = "$31f62334-edec-4fcf-b258-3ecaf2a5539e" ascii //weight: 1
        $x_1_6 = "004FEC24-35D4-4BE1-A389-31A85118FBC4" ascii //weight: 1
        $x_1_7 = "ch4XG7rr5YHaPJBGKp" ascii //weight: 1
        $x_1_8 = "GW8UdtdtFdcrwK8urZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_DG_2147798704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.DG!MTB"
        threat_id = "2147798704"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "75"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "faisigqwd" ascii //weight: 50
        $x_50_2 = "dasiowf" ascii //weight: 50
        $x_50_3 = "oasdopoasd" ascii //weight: 50
        $x_50_4 = "kgsodfdskz" ascii //weight: 50
        $x_20_5 = "Discord Link" ascii //weight: 20
        $x_1_6 = "get_CurrentDomain" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "DownloadData" ascii //weight: 1
        $x_1_9 = "ToString" ascii //weight: 1
        $x_1_10 = "Convert" ascii //weight: 1
        $x_1_11 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_UI_2147799309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.UI!MTB"
        threat_id = "2147799309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Copyright LimerBoy" ascii //weight: 1
        $x_1_2 = "$9debd99e-2b66-47b6-a327-36c777e380ef" ascii //weight: 1
        $x_1_3 = "Clipper.exe" ascii //weight: 1
        $x_1_4 = "Clipboard" ascii //weight: 1
        $x_1_5 = "get_Location" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_XO_2147799310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.XO!MTB"
        threat_id = "2147799310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2020 WinHost" ascii //weight: 1
        $x_1_2 = "$fe203f74-fe79-4d71-8ecb-268f3d87bc98" ascii //weight: 1
        $x_1_3 = "Derefner" wide //weight: 1
        $x_1_4 = "WinHost.exe" ascii //weight: 1
        $x_1_5 = "GetHINSTANCE" ascii //weight: 1
        $x_1_6 = "op_Explicit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_XO_2147799310_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.XO!MTB"
        threat_id = "2147799310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fe203f74-fe79-4d71-8ecb-268f3d87bc98" ascii //weight: 1
        $x_1_2 = {00 44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 55 49 6e 74 33 32 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 47 65 74 48 49 4e 53 54 41 4e 43 45 00}  //weight: 1, accuracy: High
        $x_1_7 = "VirtualProtect" ascii //weight: 1
        $x_1_8 = {00 41 73 73 65 6d 62 6c 79 44 65 73 63 72 69 70 74 69 6f 6e 41 74 74 72 69 62 75 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_B_2147805548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.B!MTB"
        threat_id = "2147805548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$3ba53e98-fa99-42a1-8a3a-6ba584b5a23c" ascii //weight: 1
        $x_1_2 = "set_RegistryName" ascii //weight: 1
        $x_1_3 = "ClipboardNotification" ascii //weight: 1
        $x_1_4 = "KVLC media player" ascii //weight: 1
        $x_1_5 = "shell.exe" wide //weight: 1
        $x_1_6 = "3.2.3.2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_QS_2147805918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.QS!MTB"
        threat_id = "2147805918"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$9debd99e-2b66-47b6-a327-36c777e380ef" ascii //weight: 1
        $x_1_2 = "ShinobuClipper-master" ascii //weight: 1
        $x_1_3 = "Clipper\\Clipper\\bin\\Release\\Obfuscated\\Inc.Infrastructur Host driver.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_CA_2147806307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.CA!MTB"
        threat_id = "2147806307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\jon doe\\Desktop\\Registry\\Registry\\obj\\Release\\Registry.pdb" ascii //weight: 1
        $x_1_2 = "$1d3868e2-3612-4a45-bce4-dbfae845a309" ascii //weight: 1
        $x_1_3 = "My.Computer" ascii //weight: 1
        $x_1_4 = "Registry.exe" ascii //weight: 1
        $x_1_5 = "Dispose__Instance" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_7 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_8 = "DebuggerHiddenAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ST_2147808057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ST!MTB"
        threat_id = "2147808057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ToBase64String" ascii //weight: 1
        $x_1_2 = "MemoryStream" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Rijndael" ascii //weight: 1
        $x_1_5 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_6 = "set_Key" ascii //weight: 1
        $x_1_7 = "get_CurrentDomain" ascii //weight: 1
        $x_1_8 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_9 = "$c8a6f40c-fc98-41b3-b9b4-7a63f418ff12" ascii //weight: 1
        $x_1_10 = "StringComparison" ascii //weight: 1
        $x_1_11 = "ToWin32" ascii //weight: 1
        $x_1_12 = "CreateEncryptor" ascii //weight: 1
        $x_1_13 = "get_Assembly" ascii //weight: 1
        $x_1_14 = "PasswordDeriveBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_MA_2147808211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.MA!MTB"
        threat_id = "2147808211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 69 8d 2c 00 00 01 25 17 28 ?? ?? ?? 06 13 04 06 28 ?? ?? ?? 06 1f 0d 6a 59 13 05 07 06 11 04 11 05 09 6f ?? ?? ?? 2b 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "MemoryStream" ascii //weight: 1
        $x_1_3 = "ToBase64String" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
        $x_1_7 = "IsLogging" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
        $x_1_9 = "Debugger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_MB_2147808212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.MB!MTB"
        threat_id = "2147808212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 69 8d 2b 00 00 01 25 17 28 ?? ?? ?? 06 13 04 06 28 ?? ?? ?? 06 1f 0d 6a 59 13 05 07 06 11 04 11 05 09 6f ?? ?? ?? 2b 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "MemoryStream" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "ToBase64String" ascii //weight: 1
        $x_1_7 = "ConfusedByAttribute" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "Debugger" ascii //weight: 1
        $x_1_10 = "IsLogging" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_MC_2147808213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.MC!MTB"
        threat_id = "2147808213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jgsdfsasds" ascii //weight: 1
        $x_1_2 = "Discord Link :  v1.0.0-custom" ascii //weight: 1
        $x_1_3 = "WebRequest" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "DownloadData" ascii //weight: 1
        $x_1_8 = "GetHINSTANCE" ascii //weight: 1
        $x_1_9 = "VirtualProtect" ascii //weight: 1
        $x_1_10 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_DH_2147808642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.DH!MTB"
        threat_id = "2147808642"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "WinOSDsk" ascii //weight: 20
        $x_20_2 = "WinHost" ascii //weight: 20
        $x_1_3 = "Hoting" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "Clipboard" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "GetDataPresent" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "Mutex" ascii //weight: 1
        $x_1_10 = "Regex" ascii //weight: 1
        $x_1_11 = "FileDrop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 9 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_L_2147809608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.L!MTB"
        threat_id = "2147809608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 00 48 00 6e 00 35 00 36 00 79 00 75 00 62 00 6f 00 64 00 64 00 33 00 71 00 76 00 6d 00 4d 00 38 00 33 00 4b 00 4b 00 66 00 6f 00 5a 00 55 00 63 00 46 00 75 00 72 00 31 00 47 00 4e 00 38 00 43 00 72}  //weight: 1, accuracy: High
        $x_1_2 = "5f4c7b74-3de9-4588-a6e1-46a895853bc6" ascii //weight: 1
        $x_1_3 = "GetFolderPath" ascii //weight: 1
        $x_1_4 = "ChromeUpdate.exe" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_DI_2147809834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.DI!MTB"
        threat_id = "2147809834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$a889cc40-1b24-4877-82e1-b901bbe55b1d" ascii //weight: 20
        $x_20_2 = "$afec34cc-680d-4e23-8a79-7dde51973c32" ascii //weight: 20
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerBrowsableState" ascii //weight: 1
        $x_1_7 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggingModes" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
        $x_1_11 = "CreateInstance" ascii //weight: 1
        $x_1_12 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_CM_2147811658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.CM!MTB"
        threat_id = "2147811658"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Beds-Protector" ascii //weight: 3
        $x_3_2 = "set_UseShellExecute" ascii //weight: 3
        $x_3_3 = "MD5CryptoServiceProvider" ascii //weight: 3
        $x_3_4 = "Beds-Protector-The-Quick-Brown-Fox-Jumped-Over-The-Lazy-Dog" ascii //weight: 3
        $x_3_5 = "SecurityHealthService" ascii //weight: 3
        $x_3_6 = "START CMD /C" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_CM_2147811658_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.CM!MTB"
        threat_id = "2147811658"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "System.Security.Cryptography.AesCryptoServiceProvider" ascii //weight: 3
        $x_3_2 = "{11111-22222-10009-11112}" ascii //weight: 3
        $x_3_3 = "noSXPFMbbZh2Bafej4.bKHDLoYx25MeUohwr7" ascii //weight: 3
        $x_3_4 = "{11111-22222-50001-00000}" ascii //weight: 3
        $x_3_5 = "GetDelegateForFunctionPointer" ascii //weight: 3
        $x_3_6 = "rJqNEeiWXDvJsanTbLjIo4HO" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_RPK_2147812458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.RPK!MTB"
        threat_id = "2147812458"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Clipper.exe" ascii //weight: 1
        $x_1_2 = "GetTempPath" ascii //weight: 1
        $x_1_3 = "SpecialFolder" ascii //weight: 1
        $x_1_4 = "cWallets" ascii //weight: 1
        $x_1_5 = "CheckMutex" ascii //weight: 1
        $x_1_6 = "cStartUp" ascii //weight: 1
        $x_1_7 = "dWallets" ascii //weight: 1
        $x_1_8 = "E7wDmTi0R54MaOPrgwT770N32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_MF_2147815338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.MF!MTB"
        threat_id = "2147815338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 08 13 05 14 13 08 11 05 8e 69 1e 5b 13 0c 11 05 73 ?? ?? ?? 0a 73 ?? ?? ?? 06 13 0d 16 13 16 38 ?? ?? ?? 00 11 0d 6f ?? ?? ?? 06 13 17 11 0d 6f ?? ?? ?? 06 13 18 11 04 11 17 11 18 6f ?? ?? ?? 0a 11 16 17 58 13 16 11 16 11 0c 3f ?? ?? ?? ff 11 0d}  //weight: 1, accuracy: Low
        $x_1_2 = "Debugger Detected" wide //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "CookieCollection" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "LoggerException" ascii //weight: 1
        $x_1_7 = "EventLogWatcher" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = ".compressed" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NE_2147822241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NE!MTB"
        threat_id = "2147822241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 54 00 00 0a 11 20 17 6f 55 00 00 0a 13 21 11 21 72 40 38 00 70 6f 56 00 00 0a 2d 20 7e 54 00 00 0a 11 20 6f 57 00 00 0a 72 40 38 00 70 28 58 00 00 0a 6f 29 00 00 0a 6f 59 00 00 0a de 0c}  //weight: 1, accuracy: High
        $x_1_2 = {11 16 28 5d 00 00 0a 6f 5f 00 00 0a 2c 0f 72 57 8b 00 70 28 08 00 00 06 38 bf 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AG_2147822299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AG!MTB"
        threat_id = "2147822299"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 fd 02 3c 09 0b 00 00 00 f8 00 30 00 02 00 00 01 00 00 00 4f 00 00 00 3b 00 00 00 92 00 00 00 90}  //weight: 2, accuracy: High
        $x_1_2 = "ContainsText" ascii //weight: 1
        $x_1_3 = "IsMatch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NL_2147822313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NL!MTB"
        threat_id = "2147822313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$0d9e9038-f7d8-4d29-9b9f-5e600a33a7c0" ascii //weight: 1
        $x_1_2 = {57 d5 02 fc 09 0e 00 00 00 fa 25 33 00 16 00 00 02}  //weight: 1, accuracy: High
        $x_1_3 = "Net2_Protect_Fucked_Your_Unpack" ascii //weight: 1
        $x_1_4 = "SuppressIldasmAttribute" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NH_2147822315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NH!MTB"
        threat_id = "2147822315"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 00 00 00 b8 00 00 00 07 00 00 00 04 00 00 00 6b 00 00 00 16 00 00 00 41 00 00 00 77 00 00 00 12 00 00 00 03 00 00 00 2a 00 00 00 0f 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 bf a2 3f 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 a6 00 00 00 52 00 00 00 07 01 00 00 a7 01 00 00 43 01 00 00 03 00 00 00 cc 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_K_2147824430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.K!MTB"
        threat_id = "2147824430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 25 26 2c ?? 7e ?? ?? ?? 04 28 ?? ?? ?? 06 72 ?? ?? ?? 70 28 ?? ?? ?? 06 25 26 2c 4d 00 7e ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 06 25 72 ?? ?? ?? 70 28 ?? ?? ?? 06 2c ?? 7e ?? ?? ?? 04 28 ?? ?? ?? 06 25 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ADS_2147825928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ADS!MTB"
        threat_id = "2147825928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c 01 00 fe 0c 00 00 6f ?? ?? ?? 0a fe 0c 02 00 20 01 00 00 00 fe 0e 04 00 20 fd ff ff ff 20 ac d2 1d 60 20 fc 18 6a 37 61 20 50 ca 77 57 40 10 00 00 00 20 02 00 00 00 fe 0e 04 00 fe 1c 18 00 00 01 58 00 58 fe 0e 02 00 fe 0c 02 00 00 23 00 00 00 00 00 00 00 40 23 00 00 00 00 00 00 14 40 5a 28 ?? ?? ?? 0a 3f 94 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NEC_2147827666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NEC!MTB"
        threat_id = "2147827666"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 01 01 00 0a 6f 02 01 00 0a 13 0c 08 28 0d 00 00 0a 2d 10 08 11 0c 28 03 01 00 0a 16 13 16 dd bc 02 00 00 11 05 11 0c 6f 04 01 00 0a 26 14 13 0d 72 0d 03 01 70 73 05 01 00 0a 13 0e 11 08 13 0f}  //weight: 1, accuracy: High
        $x_1_2 = "-extdummt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NED_2147827668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NED!MTB"
        threat_id = "2147827668"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bc1q7gscw77ydp0whejxh8qacwl0fwrdjhv8nqslqj" wide //weight: 1
        $x_1_2 = "0xbaCe82C4eB85bD4f77E534714D6Ff2dae07F9f47" wide //weight: 1
        $x_1_3 = "schtasks.exe" wide //weight: 1
        $x_1_4 = "SELECT * FROM AntiVirusProduct" wide //weight: 1
        $x_1_5 = "a-2eD4NLkGufXM9Uj9" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ABR_2147828760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ABR!MTB"
        threat_id = "2147828760"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {57 95 02 3c 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 40 00 00 00 17 00 00 00 3c 00 00 00 74 00 00 00 42 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = "Clipboard" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "IsLogging" ascii //weight: 1
        $x_1_5 = "GetFolderPath" ascii //weight: 1
        $x_1_6 = "get_CurrentDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_R_2147829766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.R!MTB"
        threat_id = "2147829766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bc1qg4wq3xv2r39e9jevaf3pf3rqsc6ft3vt6g5dha" wide //weight: 1
        $x_1_2 = "EvilShit\\BTC Wallet Changer" ascii //weight: 1
        $x_1_3 = "^(1|3)[1-9A-HJ-NP-Za-km-z]{26,34}$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_S_2147831081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.S!MTB"
        threat_id = "2147831081"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 b5 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 e6 00 00 00 40 00 00 00 8d 01 00 00 da 03}  //weight: 2, accuracy: High
        $x_1_2 = "RtlSetProcessIsCritical" ascii //weight: 1
        $x_1_3 = "GetTempFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NEE_2147833297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NEE!MTB"
        threat_id = "2147833297"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 07 9a 0c 08 6f 19 00 00 0a 02 28 1c 00 00 0a 2c 1d 08 72 0b 00 00 70 6f 1d 00 00 0a 72 5b 00 00 70 6f 1e 00 00 0a 14 14 6f 18 00 00 0a 26 07 17 58 0b 07 06 8e 69 32 c7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_T_2147833620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.T!MTB"
        threat_id = "2147833620"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0a 1f 0b 0b 07 06 58 0a 2a}  //weight: 2, accuracy: High
        $x_2_2 = {0a 16 0b 2b 11 06 07 93 0c 08 03 58 d1 0c 06 07 08 9d 07 17 58 0b 07 06 8e 69 32}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_P_2147833971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.P!MTB"
        threat_id = "2147833971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 38 08 6f ?? 00 00 0a 02 7b ?? 00 00 04 09 9a 6f ?? 00 00 0a 28 ?? 00 00 06 08 6f ?? 00 00 0a 02 7b ?? 00 00 04 06 9a 6f ?? 00 00 0a 28 ?? 00 00 06 31 02 09 0a 09 17 58 0d 09 02 7b ?? 00 00 04 8e 69 32 bd 02 7b ?? 00 00 04 06 9a 28 ?? 00 00 0a 02 7b}  //weight: 2, accuracy: Low
        $x_1_2 = "[a-zA-Z1-9]{27,35}$" wide //weight: 1
        $x_1_3 = "[a-zA-Z1-9]{42}$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_Y_2147834226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.Y!MTB"
        threat_id = "2147834226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1b 11 06 9a 28 ?? 00 00 0a 13 07 28 ?? 02 00 06 74 ?? 00 00 01 11 07 28 ?? 00 00 0a 6f ?? 00 00 0a 13 08 20 ?? ?? ?? 00 28 ?? 00 00 0a 8c ?? 00 00 01 13 09 11 08 75 ?? 00 00 01 6f ?? 00 00 0a 8c ?? 00 00 01 11 09 16 28 ?? 00 00 0a 13 0a 11 0a 2c 31 11 09 28 ?? 00 00 0a 14 28 ?? ?? 00 06 28 ?? ?? 00 06 11 08 74 ?? 00 00 01 28 ?? 02 00 06 74 ?? 00 00 1b 16 11 09 28}  //weight: 2, accuracy: Low
        $x_1_2 = "GetResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_RPD_2147834565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.RPD!MTB"
        threat_id = "2147834565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "92//98//48//120//91//97//45//102//65//45//70//48//45//57//93//123//52//48//125//92//98" wide //weight: 1
        $x_1_2 = "eth_address" wide //weight: 1
        $x_1_3 = "CSClipper.pdb" ascii //weight: 1
        $x_1_4 = "BtcRegex" ascii //weight: 1
        $x_1_5 = "EthRegex" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
        $x_1_7 = "LateBinding" ascii //weight: 1
        $x_1_8 = "Clipboard" ascii //weight: 1
        $x_1_9 = "LateGet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AK_2147835781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AK!MTB"
        threat_id = "2147835781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vncmxdfjkfdjhutyty587499043" wide //weight: 1
        $x_1_2 = "wepoeoifivnvcnm" wide //weight: 1
        $x_1_3 = "asdsdffgjkuouyttreerw" wide //weight: 1
        $x_1_4 = "ToInteger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AL_2147835782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AL!MTB"
        threat_id = "2147835782"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 03 8e 69 14 14 17 28 ?? 00 00 06 d6 13 07 11 07 04 5f 13 08 03 11 06 03 8e 69 14 14 17 28 ?? 00 00 06 91 13 09 08 ?? 0b 00 00 1b 11 06 16 16 02 17 8d ?? 00 00 01 25 16 11 06 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 16 16 11 09 8c ?? 00 00 01 11 08 8c ?? 00 00 01 18 28 ?? 00 00 06 8c ?? 00 00 01 18 28 ?? 00 00 06 b4 9c 11 06 17 d6}  //weight: 2, accuracy: Low
        $x_1_2 = "ToInteger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ABB_2147836074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ABB!MTB"
        threat_id = "2147836074"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "clipper.guru" wide //weight: 1
        $x_1_2 = {7b 00 30 00 7d 00 5c 00 7b 00 31 00 7d 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 7b 00 30 00 7d 00 2f 00 62 00 6f 00 74 00 2f 00 7b 00 31 00 7d 00 3f 00 7b 00 32 00 7d}  //weight: 1, accuracy: High
        $x_1_4 = "ace492e9661223449782fcc8096dc6ef6289032d08d03a7b0a92179622c35bdb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ABC_2147837207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ABC!MTB"
        threat_id = "2147837207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 25 20 00 01 00 00 6f [0-3] 0a 25 20 80 00 00 00 6f [0-3] 0a 25 18 6f [0-3] 0a 25 18 6f [0-3] 0a 06 14 6f [0-3] 0a 0b 07 02 16 02 8e 69 6f [0-3] 0a 28 [0-3] 0a 0c de}  //weight: 2, accuracy: Low
        $x_1_2 = "Decryptxx2" ascii //weight: 1
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "sdsaddwedwed" wide //weight: 1
        $x_1_5 = "Runpe.Properties.Resources" wide //weight: 1
        $x_1_6 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-96] 2f 00 54 00 6f 00 6f 00 6b 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NEAA_2147837831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NEAA!MTB"
        threat_id = "2147837831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "319d5a82-58fe-4cf6-b8c6-e2158468194f" ascii //weight: 5
        $x_2_2 = "62E6F13B53D67FDD780E20D89A6E8EE503B197AC16AC3F1D2571C147FDD324C9" ascii //weight: 2
        $x_2_3 = "seq2cR1pvdJT3LewuIN" ascii //weight: 2
        $x_2_4 = "Ldc_I4_M1" ascii //weight: 2
        $x_2_5 = "uaRU74NwKL" ascii //weight: 2
        $x_2_6 = "XPdriver.exe" ascii //weight: 2
        $x_2_7 = "pZbnhv6YB" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AM_2147838239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AM!MTB"
        threat_id = "2147838239"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 28 04 00 00 0a 0a 73 ?? 00 00 0a 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 73 ?? 00 00 0a 25 07 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0c 6f ?? 00 00 0a 28 ?? 00 00 0a 08}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "ComputeHash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_SPQB_2147838628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.SPQB!MTB"
        threat_id = "2147838628"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {7e 0e 00 00 04 08 7e 0d 00 00 04 08 91 7e 0c 00 00 04 08 7e 0c 00 00 04 8e 69 5d 91 06 58 20 ff 00 00 00 5f 61 d2 9c 08 17 58 0c 08 7e 0e 00 00 04 8e 69 17 59 fe 02 16 fe 01 0d 09 2d c2}  //weight: 7, accuracy: High
        $x_1_2 = "Lona.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ACL_2147838637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ACL!MTB"
        threat_id = "2147838637"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 dc 05 00 00 28 ?? 00 00 0a 17 72 ?? 13 00 70 12 00 73 ?? 00 00 0a 80 ?? 00 00 04 06 2d 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ACL_2147838637_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ACL!MTB"
        threat_id = "2147838637"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1d 13 07 06 72 03 01 00 70 15 16 28 ?? ?? ?? 0a 0b 1e 13 07 19 09 07 19 9a 28 ?? ?? ?? 0a 1f 20 19 15 15 28 ?? ?? ?? 0a 00 1f 09 13 07 19 07 17 9a 15 6a 16 28 ?? ?? ?? 0a 00 1f 0a 13 07 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ACL_2147838637_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ACL!MTB"
        threat_id = "2147838637"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 1f 64 28 28 00 00 0a 28 27 00 00 0a 07 28 29 00 00 0a 0c 12 02 28}  //weight: 1, accuracy: High
        $x_1_2 = {72 db 00 00 70 6f ?? 00 00 0a 25 72 eb 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 25 17 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AC_2147838879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AC!MTB"
        threat_id = "2147838879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 1f 23 28 ?? ?? ?? 0a 72 35 00 00 70 28 ?? ?? ?? 0a 13 05 11 05 18 18 73 08 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AC_2147838879_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AC!MTB"
        threat_id = "2147838879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 0b 2b 27 06 02 07 6f ?? ?? ?? 0a 7e 3a 00 00 04 07 7e 3a 00 00 04 8e 69 5d 91 61 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 07 17 58 0b 07 02}  //weight: 2, accuracy: Low
        $x_1_2 = "TrafficProgrammerv2.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AO_2147839112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AO!MTB"
        threat_id = "2147839112"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 2c 26 16 28 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 1f 19 31 15 08 6f ?? 00 00 0a 1f 24 2f 0b 7e ?? 00 00 0a 06 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AT_2147840693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AT!MTB"
        threat_id = "2147840693"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_IsAttached" ascii //weight: 1
        $x_1_2 = "get_IsAlive" ascii //weight: 1
        $x_2_3 = "M@oUCC/_I3P3?b/p\\[-P8);I8\".resources" ascii //weight: 2
        $x_2_4 = "BNG}/I9h6x|>\\*zj95u$.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_CAK_2147840784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.CAK!MTB"
        threat_id = "2147840784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 0b 2b 17 00 02 07 95 28 ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 00 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d df}  //weight: 2, accuracy: Low
        $x_2_2 = "$e6b48504-7256-461d-ab94-e984b501ad83" ascii //weight: 2
        $x_1_3 = "AdobeClipp.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ADL_2147841497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ADL!MTB"
        threat_id = "2147841497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 2e 00 00 0a 25 72 9a 0a 00 70 6f ?? ?? ?? 0a 25 72 aa 0a 00 70 28 ?? ?? ?? 06 72 00 0b 00 70 28}  //weight: 2, accuracy: Low
        $x_1_2 = "OffSmart" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_BC_2147842195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.BC!MTB"
        threat_id = "2147842195"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 1f 1a 32 0f 02 6f ?? 00 00 0a 1f 23 fe 02 16 fe 01}  //weight: 2, accuracy: Low
        $x_2_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NCA_2147842252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NCA!MTB"
        threat_id = "2147842252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 1e 00 00 0a 11 05 28 ?? 00 00 0a a5 ?? 00 00 02 28 ?? 00 00 0a 2b 0d 11 04 17 58 13 04 11 04 09 8e}  //weight: 5, accuracy: Low
        $x_1_2 = "STEAM TRADE LINK" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_MG_2147842624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.MG!MTB"
        threat_id = "2147842624"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 08 13 07 7e 01 00 00 04 6f 18 00 00 0a 14 17 8d 01 00 00 01 13 0e 11 0e 16 11 07 a2 11 0e 6f 1c 00 00 0a 26 2b 17 7e 01 00 00 04 6f 18 00 00 0a 14 16}  //weight: 5, accuracy: High
        $x_1_2 = "CheckForInternetConnection" ascii //weight: 1
        $x_1_3 = "add_Shutdown" ascii //weight: 1
        $x_1_4 = "GetActiveProcessFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NBL_2147842653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NBL!MTB"
        threat_id = "2147842653"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {63 20 6d 86 b2 26 58 66 20 ?? ?? ?? f6 59 20 ?? ?? ?? 09 58 20 ?? ?? ?? f3 61 20 ?? ?? ?? 14 61 5f 91 fe 09 02 00 60 61 d1 9d}  //weight: 5, accuracy: Low
        $x_1_2 = "FNinternal.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NPB_2147842957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NPB!MTB"
        threat_id = "2147842957"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 02 07 6f 2d 00 00 0a 7e ?? ?? 00 04 07 7e ?? ?? 00 04 8e 69 5d 91 61 28 ?? ?? 00 0a 6f 67 00 00 0a 26 07 17 58 0b}  //weight: 5, accuracy: Low
        $x_1_2 = "O.N.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_CXS_2147843364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.CXS!MTB"
        threat_id = "2147843364"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 02 07 6f ?? ?? ?? ?? 25 26 7e ?? ?? ?? ?? 07 7e ?? ?? ?? ?? 8e 69 5d 91 61 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 25 26 26 07 17 58 0b 07 02 6f ?? ?? ?? ?? 25 26 32}  //weight: 5, accuracy: Low
        $x_1_2 = "ContainsKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_GFX_2147843390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GFX!MTB"
        threat_id = "2147843390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "H4sIAAAAAAAEACtOzihJLM4u1kutSAUA9QsHRwwAAAA=" ascii //weight: 1
        $x_1_2 = "H4sIAAAAAAAEAPPwsMrNBQAO/K06BQAAAA==" ascii //weight: 1
        $x_1_3 = "H4sIAAAAAAAEANNLSiwBAJz3dAEEAAAA" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ABLO_2147843436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ABLO!MTB"
        threat_id = "2147843436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PokemonSystem.Resources.resources" ascii //weight: 2
        $x_1_2 = "PokemonSystem" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_DAJ_2147843856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.DAJ!MTB"
        threat_id = "2147843856"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {93 e3 cf e6 60 69 57 e4 e0 33 4d f2 c0 ee 7c f8 7d 6e 3a 77 59 64 8e 27 ed 73 a6 12 76 18 f5 49 21 b0 d4 04 dc 3d 99 d1 05 7d cb 52 d4 02 6d 44 75 a7 a3 ae 0a 61 ba 01 f4 4b db 02 ad}  //weight: 2, accuracy: High
        $x_2_2 = {c4 81 eb df b6 53 9a df 2b e9 cb f8 35 e5 66 4a bd 39 72 d2 03 ab ff dc ab 4d 3a d6 00 82 0b 88 c8 33 07 cd 32 c0 2d 6b 6d 70 53 32 e8 3b 1d c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_CSRR_2147843978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.CSRR!MTB"
        threat_id = "2147843978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 91 0c 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32}  //weight: 5, accuracy: High
        $x_5_2 = {28 0a 00 00 06 0a 28 ?? ?? ?? ?? 06 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0b dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_MBCV_2147844227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.MBCV!MTB"
        threat_id = "2147844227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$5a6a535e-9675-4f59-bc91-5bb42152cf80" ascii //weight: 5
        $x_1_2 = "DownloadFile" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "GetFolderPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_PSLY_2147846180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.PSLY!MTB"
        threat_id = "2147846180"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 34 00 00 0a 7e 01 00 00 04 02 08 6f 35 00 00 0a 28 36 00 00 0a a5 01 00 00 1b 0b 11 07 20 fb 9d aa 47 5a 20 c4 30 82 6d 61 38 98 fe ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_C_2147846854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.C!MTB"
        threat_id = "2147846854"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 b5 02 3c 09 07 00 00 00 00 00 00 00 00 00 00 01 00 00 00 7a 00 00 00 26 00 00 00 c6}  //weight: 2, accuracy: High
        $x_1_2 = ".NET Reactor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_BE_2147847019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.BE!MTB"
        threat_id = "2147847019"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WinServiceSE.g.resources" ascii //weight: 2
        $x_2_2 = "WinServiceSE.pdb" ascii //weight: 2
        $x_1_3 = "GetFolderPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_RDG_2147848264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.RDG!MTB"
        threat_id = "2147848264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "26b93190-29d0-4bef-834a-b55169683d1e" ascii //weight: 1
        $x_1_2 = "ssscc" ascii //weight: 1
        $x_1_3 = "w5etwzi0des" ascii //weight: 1
        $x_1_4 = "Z4q4bUV4G2a2AkSpDc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_MAAO_2147848440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.MAAO!MTB"
        threat_id = "2147848440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4N~5K~90~00~03~00~00~00~04~00~00~00~PP~PP~00~" wide //weight: 1
        $x_1_2 = "1P~LK~0O~00~L4~09~MN~21~L8~01~4M~MN~" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_CXIS_2147848747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.CXIS!MTB"
        threat_id = "2147848747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "whFqWGZFcsYskI" ascii //weight: 1
        $x_1_2 = "kDZvCuKOkg" ascii //weight: 1
        $x_1_3 = "ocvTvHtfUt" ascii //weight: 1
        $x_1_4 = "uQYTkEzeCoGKZr" ascii //weight: 1
        $x_1_5 = "AaAbPOOrBhdjpO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_F_2147848818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.F!MTB"
        threat_id = "2147848818"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "StartChanger" ascii //weight: 2
        $x_2_2 = "Telegram.Bot" ascii //weight: 2
        $x_2_3 = "MainShit" ascii //weight: 2
        $x_2_4 = "Regex.Match(GetText" ascii //weight: 2
        $x_2_5 = "Convert.ToString(PatternRegex" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ABS_2147849337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ABS!MTB"
        threat_id = "2147849337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 4d 12 00 28 ?? 00 00 0a 0b 73 ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 0c 08 07 6f ?? 00 00 0a 28}  //weight: 10, accuracy: Low
        $x_10_2 = {00 00 0a 19 5d 59 0a 02 1f 41 06 73 ?? 00 00 0a 28 ?? 00 00 0a 0b 28 ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ABT_2147849338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ABT!MTB"
        threat_id = "2147849338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 3b 00 1b 8d ?? 00 00 01 25 16 72 ?? 00 00 70 a2 25 17 28 ?? 00 00 0a a2 25 18 72 ?? 00 00 70 a2 25 19 11 05 a2 25 1a 72 ?? 00 00 70 a2 28 ?? 00 00 0a 18 16 15 28 ?? 00 00 0a 26 00 00 00 28 ?? 00 00 06 00}  //weight: 10, accuracy: Low
        $x_10_2 = {74 06 00 00 1b 13 05 07 11 05 73 ?? 00 00 0a 72 ?? 03 00 70 72 ?? 03 00 70 6f ?? 00 00 0a 00 02 7b ?? 00 00 04 02 7b ?? 00 00 04 07 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06 11 06 6f ?? 00 00 0a 20 ?? 00 00 00 fe 01 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AACK_2147849372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AACK!MTB"
        threat_id = "2147849372"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {04 08 16 07 1f 0f 1f 10 28 ?? 01 00 06 7e ?? 00 00 04 06 07 28 ?? 00 00 06 7e ?? 00 00 04 06 18 28 ?? 00 00 06 7e ?? 00 00 04 06 19 28 ?? 00 00 06 7e ?? 00 00 04 06 28 ?? 00 00 06 0d 7e ?? 00 00 04 09 03 16 03 8e 69 28 ?? 00 00 06 2a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AR_2147849530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AR!MTB"
        threat_id = "2147849530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 02 07 6f ?? 00 00 0a 7e ?? 00 00 04 07 7e ?? 00 00 04 8e 69 5d 91 61 28 ?? 00 00 0a 6f ?? 00 00 0a 26 07 17 58 0b 07 02 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "AddClipboardFormatListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ABD_2147849710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ABD!MTB"
        threat_id = "2147849710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 7e 07 00 00 0a 0a 7e 07 00 00 0a 0b 20 f4 01 00 00 28 08 00 00 0a 00 00 28 09 00 00 0a 16 fe 01 13 05 11 05 ?? ?? ?? ?? ?? 00 28 0a 00 00 0a 0b 07 06 28 0b 00 00 0a 16 fe 01 13 05 11 05 3a f4 00 00 00 00 72 ?? ?? ?? ?? 73 0c 00 00 0a 07 28 0d 00 00 0a 16 fe 01 13 05 11 05 2d 36 00 7e 01 00 00 04 2d 13 14 fe 06 03 00 00 06 73 0e 00 00 0a 80 01 00 00 04 2b 00 7e 01 00 00 04}  //weight: 1, accuracy: Low
        $x_1_2 = {13 04 11 04 16 6f 10 00 00 0a 00 11 04 6f 11 00 00 0a 00 00 07 0a 00 00 00 de 05 26 00 00 de 00 00 00 17 13 05 38 b5 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AADU_2147850026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AADU!MTB"
        threat_id = "2147850026"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 04 1d 3a ?? 00 00 00 26 26 00 07 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 16 39 ?? 00 00 00 26 02 73 ?? 00 00 0a 18 3a ?? 00 00 00 26 00 09 08 16 73 ?? 00 00 0a 16 2c 48 26 16 2d 01 00 73 ?? 00 00 0a 13 05 00 1d 2c fc 11 04 11 05 6f ?? 00 00 0a 00 11 05 6f ?? 00 00 0a 0a 1b 2c 01 00 de 0d 11 05 2c 08 11 05 6f ?? 00 00 0a 00 dc}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_BJ_2147850699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.BJ!MTB"
        threat_id = "2147850699"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "lJM9KtEvm0rA2R3W13L7kwSkg6Y=" ascii //weight: 2
        $x_2_2 = "u8XF+Z+57IUVzb+biRqCAS3SSgo=" ascii //weight: 2
        $x_2_3 = "V2luZG93c0FwcGxpY2F0aW9uM" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AAEO_2147850705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AAEO!MTB"
        threat_id = "2147850705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1e 2c 27 38 a5 00 00 00 38 a6 00 00 00 38 a7 00 00 00 00 38 ab 00 00 00 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 02 73 ?? 00 00 0a 0d 00 09 08 16 73 ?? 00 00 0a 13 04 16 2d 01 00 73 ?? 00 00 0a 13 05 00 1d 2c fc 11 04 11 05 6f ?? 00 00 0a 00 11 05 6f ?? 00 00 0a 0a 1b 2c 01 00 de 0d 11 05 2c 08 11 05 6f ?? 00 00 0a 00 dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AAFC_2147850719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AAFC!MTB"
        threat_id = "2147850719"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0b 06 16 fe 0e 03 00 20 f8 ff ff ff 20 5d 3c 3f 74 20 8e ff 6d 1f 61 20 d3 c3 52 6b 40 ?? 00 00 00 20 02 00 00 00 fe 0e 03 00 fe ?? ?? 00 00 01 58 00 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 06 6f ?? 00 00 0a 07 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_PSRN_2147850750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.PSRN!MTB"
        threat_id = "2147850750"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 09 00 00 06 0a 28 08 00 00 0a 06 6f 09 00 00 0a 28 08 00 00 06 75 01 00 00 1b 0b 07 16 07 8e 69 28 0a 00 00 0a 07 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_PSSX_2147851455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.PSSX!MTB"
        threat_id = "2147851455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f ac 00 00 0a 06 07 6f ad 00 00 0a 17 73 5d 00 00 0a 25 02 16 02 8e 69 6f ae 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_EA_2147851545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.EA!MTB"
        threat_id = "2147851545"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9bacadaeafagaha" wide //weight: 1
        $x_1_2 = "is tampered." wide //weight: 1
        $x_1_3 = "ClipperBuild.g.resources" ascii //weight: 1
        $x_1_4 = "costura.dotnetzip.pdb.compressed" ascii //weight: 1
        $x_1_5 = "IsClipboardFormatAvailable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_PSTB_2147851565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.PSTB!MTB"
        threat_id = "2147851565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 20 54 93 ca 40 28 ?? 00 00 06 02 20 8a 92 ca 40 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 06 2c 07 06 73 37 00 00 0a 2a 14 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AAID_2147851991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AAID!MTB"
        threat_id = "2147851991"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {04 08 16 07 1f 0f 1f 10 28 ?? 00 00 06 7e ?? 00 00 04 06 07 28 ?? 00 00 06 7e ?? 00 00 04 06 18 28 ?? 00 00 06 7e ?? 00 00 04 06 19 28 ?? 00 00 06 7e ?? 00 00 04 06 28 ?? 00 00 06 0d 7e ?? 00 00 04 09 02 16 02 8e 69 28 ?? 00 00 06 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_BM_2147852537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.BM!MTB"
        threat_id = "2147852537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 06 25 26 0a 06 28 ?? ?? 00 06 25 26 03 50 28 ?? ?? 00 06 25 26 28 ?? ?? 00 06 25 26 0b 28}  //weight: 2, accuracy: Low
        $x_2_2 = {0c 08 07 28 ?? ?? 00 06 08 28 ?? 00 00 06 25 26 28 ?? ?? 00 06 08 28}  //weight: 2, accuracy: Low
        $x_2_3 = {00 00 06 25 26 02 50 8e 69 28 ?? ?? 00 06 25 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_BL_2147853406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.BL!MTB"
        threat_id = "2147853406"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JTOERfU6Cjih3gM4zyfsvAxSiWLJliwmNiALqn3r6SO2E" ascii //weight: 2
        $x_2_2 = "t7t91EVbBpI89JvkZytU7inVRKF4iryo3uL9tQjcnxeTF" ascii //weight: 2
        $x_2_3 = "pUX2m88l2E4a6ToSaKRGFZ39xm69Fs5aQSY3aItq7b8C3" ascii //weight: 2
        $x_2_4 = "Mj0z3vFnkGbVQASczroA3Ku7NEe7l51RxtMIeamSq5Z04" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NQC_2147889498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NQC!MTB"
        threat_id = "2147889498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 17 7d 07 00 00 04 72 ?? ?? 00 70 18 73 ?? ?? 00 0a 0a 02 06 28 ?? ?? 00 0a 00 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "CryptoLauncher.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_MBIM_2147889518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.MBIM!MTB"
        threat_id = "2147889518"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sgfhjffffgdrfhddfhfffadfsfsscfgdb" ascii //weight: 1
        $x_1_2 = "gffssfdsx" ascii //weight: 1
        $x_1_3 = "hjfdfhgfadffddcdffffskhj" ascii //weight: 1
        $x_1_4 = "fsffggfgfafad" ascii //weight: 1
        $x_1_5 = "hdfffafsfsdkfsh" ascii //weight: 1
        $x_1_6 = "RijndaelManaged" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_PSXH_2147890473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.PSXH!MTB"
        threat_id = "2147890473"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 07 28 1f 00 00 0a 0d 09 14 fe 03 13 04 11 04 39 b5 00 00 00 00 07 72 7f 00 00 70 6f 23 00 00 0a 13 05 11 05 2c 12 00 72 85 00 00 70 28 24 00 00 0a 00 00 38 90}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NGW_2147892261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NGW!MTB"
        threat_id = "2147892261"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 85 00 00 0a 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0c 08 02 16 02 8e 69 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "ReadProcessMemory" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "OpenProcess" ascii //weight: 1
        $x_1_5 = "trades.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_PTBK_2147895775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.PTBK!MTB"
        threat_id = "2147895775"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 77 00 00 70 6f 1f 00 00 0a 25 72 95 00 00 70 02 72 ab 00 00 70 28 ?? 00 00 0a 6f 2e 00 00 0a 25 17 6f 2f 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_KA_2147896283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.KA!MTB"
        threat_id = "2147896283"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 46 12 04 28 ?? 00 00 0a 13 05 11 05 06 28 ?? 00 00 06 13 06 11 06 08 32 2e 11 06 08 33 0b 07 11 05 6f ?? 00 00 0a 26 2b 1e 11 06 08 31 19}  //weight: 5, accuracy: Low
        $x_5_2 = "1EN9DmsnRk9GLatXp7v2WqUnmB6XznDdgv" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ABAT_2147896517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ABAT!MTB"
        threat_id = "2147896517"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PEGASUS_LIME.Design.Algorithmos.Overkill" ascii //weight: 1
        $x_1_2 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "PEGASUS_LIME.Properties.Resources.resources" ascii //weight: 1
        $x_1_7 = "PEGASUS_LIME.Properties" ascii //weight: 1
        $x_1_8 = "$13465ce4-1987-446b-b6bb-0c587bd6b35f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_KAB_2147900308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.KAB!MTB"
        threat_id = "2147900308"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 00 00 fe 09 00 00 fe 0c 01 00 6f ?? 00 00 0a 20 ?? ?? ?? ?? 61 d1 fe 0e 02 00 fe 0d 02 00 28 ?? 00 00 0a 28 ?? 00 00 0a fe 0e 00 00 fe 0c 01 00 20 ?? 00 00 00 58 fe 0e 01 00 fe 0c 01 00 fe 09 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_BY_2147900605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.BY!MTB"
        threat_id = "2147900605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 09 06 94 58 08 06 94 58 20 ?? ?? ?? 00 5d 13 05 09 06 94 0b 09 06 09 11 05 94 9e 09 11 05 07 9e 06 17 58 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ATD_2147900827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ATD!MTB"
        threat_id = "2147900827"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 09 00 00 28 07 00 00 0a fe 0e 00 00 7e 08 00 00 0a fe 0e 01 00 fe 0c 00 00 39 8b 00 00 00 fe 0c 00 00 8e 39 81 00 00 00 fe 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_CC_2147900997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.CC!MTB"
        threat_id = "2147900997"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "clipboard_check_delay" ascii //weight: 2
        $x_2_2 = "replace_clipboard" ascii //weight: 2
        $x_2_3 = "clipboard_changed" ascii //weight: 2
        $x_2_4 = "autorun_enabled" ascii //weight: 2
        $x_2_5 = "autorun_name" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_RDJ_2147903219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.RDJ!MTB"
        threat_id = "2147903219"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 07 6f 2f 00 00 0a 17 73 30 00 00 0a 25 02 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_SG_2147903356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.SG!MTB"
        threat_id = "2147903356"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "zgfn.My" ascii //weight: 2
        $x_1_2 = "fgxg.exe" ascii //weight: 1
        $x_1_3 = "$a3392dc3-d8ff-4069-8782-0ae8a1125281" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ClipBanker_KAC_2147905517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.KAC!MTB"
        threat_id = "2147905517"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 9a 0c 06 08 6f ?? 00 00 0a 2c 1d d0 ?? 00 00 02 28 ?? 00 00 0a 08 28 ?? 00 00 0a a5 ?? 00 00 02 73 ?? 00 00 0a 0b 2b 0e 11 05 17 58 13 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NB_2147906030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NB!MTB"
        threat_id = "2147906030"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6e 5f 1f 18 63 d2 61 d2 81 ?? 00 00 01 11 0b 1a 58 13 0b}  //weight: 10, accuracy: Low
        $x_1_2 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NC_2147906430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NC!MTB"
        threat_id = "2147906430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {59 17 63 5f 91 04 60 61 d1 9d 06}  //weight: 10, accuracy: High
        $x_1_2 = "Clipboard" ascii //weight: 1
        $x_1_3 = "AsyncClipboardManager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_CG_2147906739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.CG!MTB"
        threat_id = "2147906739"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Select * from Win32_ComputerSystem" wide //weight: 2
        $x_2_2 = "This is not a VMware virtual machine" wide //weight: 2
        $x_2_3 = "-WindowStyle Hidden Start-Sleep 5;Start-Process" wide //weight: 2
        $x_2_4 = "\\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,35}\\b" wide //weight: 2
        $x_2_5 = "\\b0x[a-fA-F0-9]{40}\\b" wide //weight: 2
        $x_2_6 = "\\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\\b" wide //weight: 2
        $x_2_7 = "\\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\\b" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_CI_2147906772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.CI!MTB"
        threat_id = "2147906772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 6f ?? 00 00 0a 25 6f ?? 00 00 0a 6f ?? 00 00 0a 7b ?? 00 00 04 74 ?? 00 00 01 74 ?? 00 00 01 25 0a 28 ?? 00 00 0a 16 fe}  //weight: 2, accuracy: Low
        $x_2_2 = {01 13 04 1f ?? 58 1e 5c 18 5a 17 59 e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_GZX_2147908573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GZX!MTB"
        threat_id = "2147908573"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 04 09 11 04 09 6f ?? ?? ?? 0a 00 23 ?? ?? ?? ?? ?? ?? ?? ?? 23 ?? ?? ?? ?? ?? ?? ?? ?? 28 ?? ?? ?? 0a 58 28 ?? ?? ?? 0a 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 11 04 09 6f ?? ?? ?? 0a 00 23 ?? ?? ?? ?? ?? ?? ?? ?? 23 ?? ?? ?? ?? ?? ?? ?? ?? 28 ?? ?? ?? 0a 58 28 ?? ?? ?? 0a 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 00 23 ?? ?? ?? ?? ?? ?? ?? ?? 23 ?? ?? ?? ?? ?? ?? ?? ?? 58 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 17 6f ?? ?? ?? 0a 08 09 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 05}  //weight: 10, accuracy: Low
        $x_1_2 = "nahu112.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_GNK_2147917071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GNK!MTB"
        threat_id = "2147917071"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {08 09 06 09 91 07 09 07 8e 69 5d 91 61 d2 9c 09 16 2d ea 17 58 0d 09 06 8e 69 32 e4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AYA_2147919626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AYA!MTB"
        threat_id = "2147919626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$069e7dba-3b68-45b4-a873-42487370cb2e" ascii //weight: 2
        $x_1_2 = "Steal.g.resources" ascii //weight: 1
        $x_1_3 = "Steal.exe" ascii //weight: 1
        $x_1_4 = "IEJAEJKFGOACAMHDNODBLDHPKADLKKOHCDHE" ascii //weight: 1
        $x_1_5 = "Debugger Detected" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AYA_2147919626_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AYA!MTB"
        threat_id = "2147919626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "$cb79da84-98cb-4d83-b315-032d3575881b" ascii //weight: 3
        $x_1_2 = "/create /sc MINUTE /mo 1 /tn \"Windows Service\" /tr" wide //weight: 1
        $x_1_3 = "taskhostmgr64.exe" wide //weight: 1
        $x_1_4 = "DebuggingModes" ascii //weight: 1
        $x_1_5 = "KMSAutoLite.Properties" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_CCJB_2147921779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.CCJB!MTB"
        threat_id = "2147921779"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c 02 00 25 20 01 00 00 00 58 fe 0e 02 00 6f ?? 00 00 0a 61 d2 6f ?? 00 00 0a fe 0c 02 00 fe 0c 00 00 6f ?? 00 00 0a 5d fe 0e 02 00 fe 0c 04 00 20 01 00 00 00 58 fe 0e 04 00 fe 0c 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_PDDH_2147923422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.PDDH!MTB"
        threat_id = "2147923422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 06 60 61 20 11 88 ba 4c 61 16 33 02 2b 36 1f 1e 06 1f 21 5a 06 1f 1f 5a 58 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ND_2147924598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ND!MTB"
        threat_id = "2147924598"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 11 04 07 09 06 25 17 58 0a 6f 03 00 00 0a 61 d2 6f 04 00 00 0a 06 09 6f 05 00 00 0a 5d 0a 11 05 17 58}  //weight: 2, accuracy: High
        $x_1_2 = "e4b00ba3-65db-4000-ac11-e391f3221a5c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_MX_2147926200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.MX!MTB"
        threat_id = "2147926200"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 28 0d 00 00 06 0a 06 28 10 00 00 06 0b}  //weight: 1, accuracy: High
        $x_1_2 = {06 28 11 00 00 06 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NIT_2147927783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NIT!MTB"
        threat_id = "2147927783"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 2c 6d 07 6f ?? 00 00 0a 0c 16 0d 2b 48 08 09 9a 13 04 07 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 11 04 1c 28 ?? 00 00 06 28 ?? 00 00 0a 2c 1f 11 05 7e 36 00 00 04 28 ?? 00 00 0a 2c 0d 07 11 04 7e 36 00 00 04 6f ?? 00 00 0a 17 0a 2b 02 16 0a 09 17 58 0d 09 08 8e 69 32 b2 06 2d 11 07 1c 28 ?? 00 00 06 7e 36 00 00 04 6f ?? 00 00 0a de 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ACB_2147929218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ACB!MTB"
        threat_id = "2147929218"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 25 17 02 a2 25 18 72 ?? ?? ?? 70 a2 25 19 03 a2 25 1a 72 ?? ?? ?? 70 a2 25 1b 04 a2 28 ?? 00 00 0a 6f ?? 00 00 0a 00 08 0b 07 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ACB_2147929218_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ACB!MTB"
        threat_id = "2147929218"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0b 2b 17 7e 01 00 00 04 07 7e 01 00 00 04 07 9a 28 ?? 00 00 06 a2 07 17 58 0b 07 7e 01 00 00 04 8e 69}  //weight: 2, accuracy: Low
        $x_3_2 = {d2 1f 18 26 26 06 13 04 16 13 05 11 04 12 05 28 ?? 00 00 0a 07 09 02 09 6f ?? 00 00 0a d2 17 61 d1 9d de 0c}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ACB_2147929218_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ACB!MTB"
        threat_id = "2147929218"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pnes1518TB" ascii //weight: 1
        $x_2_2 = "H4sIAAAAAAAEACvLLU8sSi1OLSrLTE7VS61IBQC0nYUtEQAAAA==" wide //weight: 2
        $x_3_3 = "H4sIAAAAAAAEAAt29XF1DlHQUnAL8vdVCM/MMzaKD8gvKnHOz8tLTS7JLwIA87vuiyEAAAA=" wide //weight: 3
        $x_4_4 = "H4sIAAAAAAAEAAt29XF1DlHQUnAL8vdVCM/MMzaKD8tMSc13zs8rKcrPyUktAgAHop8JIwAAAA==" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ANIA_2147930115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ANIA!MTB"
        threat_id = "2147930115"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 16 07 1f 0f 1f 10 28 ?? 01 00 06 7e ?? 00 00 04 06 07 28 ?? 01 00 06 7e ?? 01 00 04 06 18 28 ?? 01 00 06 7e ?? 01 00 04 06 19 28 ?? 01 00 06 7e ?? 01 00 04 06 28 ?? 01 00 06 0d 7e ?? 01 00 04 09 03 16 03 8e 69 28 ?? 01 00 06 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AENA_2147935203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AENA!MTB"
        threat_id = "2147935203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 1b 58 1b 59 91 61 03 08 20 10 02 00 00 58 20 0f 02 00 00 59 1a 59 1a 58 03 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 59 20 fb 00 00 00 58 1a 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_EAAJ_2147935420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.EAAJ!MTB"
        threat_id = "2147935420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 02 6f 1b 00 00 0a 07 59 6f 1c 00 00 0a 03 03 6f 1b 00 00 0a 07 59 6f 1c 00 00 0a fe 01 16 fe 01 0c 08 2c 03 00 2b 24 06 17 58 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NJK_2147943564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NJK!MTB"
        threat_id = "2147943564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$" ascii //weight: 2
        $x_1_2 = "^(?:[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})$" ascii //weight: 1
        $x_1_3 = "^(bitcoincash:)?(q|p)[a-z0-9]{41}" ascii //weight: 1
        $x_1_4 = "DecryptData" ascii //weight: 1
        $x_1_5 = "EncryptData" ascii //weight: 1
        $x_1_6 = "ProcessClipboardContent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NJM_2147944242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NJM!MTB"
        threat_id = "2147944242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {60 66 11 06 5a 17 5f 16 2e 11 00 11 06 66 1f 40 5f 1f 40}  //weight: 2, accuracy: High
        $x_1_2 = "/c schtasks /create /tn \"{0}\" /tr \"{1}\" /SC MINUTE /MO 1 /IT /F" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_4 = "uDK6q4Jgad9g8NTMKuWJaovRBCxvKXMYztau" ascii //weight: 1
        $x_1_5 = "UserOOBEBroker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_SL_2147944857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.SL!MTB"
        threat_id = "2147944857"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0a 16 7e 05 00 00 04 12 00 73 1c 00 00 0a 26 06 2d 06 17 28 1d 00 00 0a 2a}  //weight: 2, accuracy: High
        $x_2_2 = "predst014" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_SM_2147944858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.SM!MTB"
        threat_id = "2147944858"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 58 0a 00 06 02 fe 04 0d 09 2d b0}  //weight: 2, accuracy: High
        $x_2_2 = "CoinClipper" ascii //weight: 2
        $x_2_3 = "cc_Config.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_PLZ_2147944893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.PLZ!MTB"
        threat_id = "2147944893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 01 00 00 70 fe 0e 00 00 fe 09 00 00 6f ?? 00 00 0a 8d 3f 00 00 01 fe 0e 01 00 20 00 00 00 00 fe 0e 02 00 20 00 00 00 00 fe 0e 03 00 38 50 00 00 00 fe 0c 01 00 fe 0c 03 00 fe 09 00 00 fe 0c 03 00 6f ?? 00 00 0a fe 0c 00 00 fe 0c 02 00 25 20 01 00 00 00 58 fe 0e 02 00 6f ?? 00 00 0a 61 d2 9c fe 0c 02 00 fe 0c 00 00 6f ?? 00 00 0a 5d fe 0e 02 00 fe 0c 03 00 20 01 00 00 00 58 fe 0e 03 00 fe 0c 03 00 fe 09 00 00 6f ?? 00 00 0a 3f 9e}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_GAF_2147945544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GAF!MTB"
        threat_id = "2147945544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tethersol" ascii //weight: 2
        $x_1_2 = "ProcessClipboardContent" ascii //weight: 1
        $x_1_3 = "ClipboardListener" ascii //weight: 1
        $x_1_4 = "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$" ascii //weight: 1
        $x_1_5 = "^(?:[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})$" ascii //weight: 1
        $x_1_6 = "(?:^0x[a-fA-F0-9]{40}$)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_GTD_2147946562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.GTD!MTB"
        threat_id = "2147946562"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1f 31 13 1d 1f 2d 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 33 0a 18 13 1d fe ?? ?? ?? ?? ?? 58 00 3b ?? ?? ?? ?? 07 6f ?? ?? ?? ?? 07 6f ?? ?? ?? ?? 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ACAB_2147946972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ACAB!MTB"
        threat_id = "2147946972"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 08 06 7e 44 00 00 04 06 28 ?? 01 00 06 28 ?? 01 00 06 28 ?? 01 00 06 9d 08 17 13 04 1f fd 20 73 dc 05 4a 20 4f ?? db 25 61 20 3c 4c de 6f 33 0a 18 13 04 fe 1c 0d 00 00 1b 58 00 58 0c 08 02 32 be}  //weight: 4, accuracy: Low
        $x_2_2 = "ILoveYourMother" ascii //weight: 2
        $x_1_3 = "Confuser.Core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_PGCB_2147947944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.PGCB!MTB"
        threat_id = "2147947944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 16 0b 2b 12 06 07 06 07 91 1f ?? 07 ?? 5d 58 61 d2 9c 07 17 58 0b 07 06 8e 69 32 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0a 16 0b 2b 12 06 07 06 07 91 1f ?? 07 ?? 5d 58 61 d2 9c 07 17 58 0b 07 06 8e 69 32 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NJO_2147948135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NJO!MTB"
        threat_id = "2147948135"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "388355c4-8561-44c0-8e69-3025c1f23d16" ascii //weight: 2
        $x_1_2 = "Clipper.My.Resources" ascii //weight: 1
        $x_1_3 = "PatternRegex" ascii //weight: 1
        $x_1_4 = "ClipboardNotification" ascii //weight: 1
        $x_1_5 = "currentClipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AYBB_2147948741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AYBB!MTB"
        threat_id = "2147948741"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 25 2d 17 26 7e 2f 00 00 04 fe 06 06 00 00 2b 73 24 00 00 0a 25 80 30 00 00 04 28 ?? 00 00 06 25 16 0a 1f fc 20 ad b4 fb 68 20 c5 bd 15 3e 61 20 68 09 ee 56 33 09 18 0a fe 1c 02 00 00 1b 58 00 28 ?? 00 00 06 28 ?? 00 00 06 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "Confuser.Core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NIA_2147949131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NIA!MTB"
        threat_id = "2147949131"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "5331bd34-4027-4657-b2bf-b1a696b1b1b7" ascii //weight: 2
        $x_1_2 = "(xrb_|nano_)[13456789abcdefghijkmnopqrstuwxyz]" ascii //weight: 1
        $x_1_3 = "(NA|NB|NC|ND)[a-zA-z0-9]{38}" ascii //weight: 1
        $x_1_4 = "(terra1)[0-9a-z]{38}" ascii //weight: 1
        $x_1_5 = "(cosmos1)[0-9a-z]{38}" ascii //weight: 1
        $x_1_6 = "(bitcoincash:)?(q|p)[a-z0-9]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ANCB_2147949194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ANCB!MTB"
        threat_id = "2147949194"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 11 06 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 11 06 1e 63 13 06}  //weight: 4, accuracy: Low
        $x_2_2 = {07 11 07 6f ?? 00 00 0a 1f 3a 5a 11 06 58 13 08}  //weight: 2, accuracy: Low
        $x_1_3 = "Confuser.Core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_NIB_2147949205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.NIB!MTB"
        threat_id = "2147949205"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "#=qxgctuP6ZqFCjO9UkQvYTjcQw0g3HrvLH9U6VYUyVE$I=" ascii //weight: 2
        $x_1_2 = "#=qr9YotdsWVwSdbrj6D5OlmHWwwJVhBeBIJ5J461Az$DQ=" ascii //weight: 1
        $x_1_3 = "System.Security.Cryptography.CAPIBase+CMSG_KEY_AGREE_PUBLIC_KEY_RECIPIENT_INFO" ascii //weight: 1
        $x_1_4 = "set_UseShellExecute" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AHD_2147949366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AHD!MTB"
        threat_id = "2147949366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 72 0e 0e 00 70 1b 6f 40 00 00 0a 2c 0c 02 6f 41 00 00 0a 1f 2a fe 01 2b 01 16 0d 09 13 27 11 27 2c 2f}  //weight: 10, accuracy: High
        $x_5_2 = {6f 4a 00 00 0a 13 07 12 07 28 4b 00 00 0a 58 0b 08 11 06 6f 4a 00 00 0a 13 07 12 07 28 4c 00 00 0a 28 4d 00 00 0a 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_AADB_2147949635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.AADB!MTB"
        threat_id = "2147949635"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 11 07 11 08 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 11 08 1e 63 13 06}  //weight: 4, accuracy: Low
        $x_2_2 = {07 11 07 6f ?? 00 00 0a 1f 3a 5a 11 06 58 13 08}  //weight: 2, accuracy: Low
        $x_1_3 = "Confuser.Core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_SPZC_2147949690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.SPZC!MTB"
        threat_id = "2147949690"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "kto prochital tot shluha" ascii //weight: 2
        $x_1_2 = "ILoveYourMother" ascii //weight: 1
        $x_1_3 = "H4sIAAAAAAAEACvLLU8sSi0pSqzUS61IBQAfPEEfDgAAAA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_PCW_2147950374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.PCW!MTB"
        threat_id = "2147950374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 07 11 08 20 ff 00 00 00 5f d2 6f 2e 00 00 0a 11 0a 20 ca e8 83 06 5a 20 6f 9c c1 c0 61 38 3f fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_ACLB_2147950745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.ACLB!MTB"
        threat_id = "2147950745"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0c 2b 1b 07 08 06 08 91 7e 33 00 00 04 08 7e 33 00 00 04 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 06 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ClipBanker_2147951059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ClipBanker.MTH!MTB"
        threat_id = "2147951059"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ClipBanker"
        severity = "Critical"
        info = "MTH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 28 08 00 00 0a 0a 06 8e 69 8d 1f 00 00 01 0b 16 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

