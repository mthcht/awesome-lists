rule Trojan_MSIL_ElysiumStealer_DA_2147779169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DA!MTB"
        threat_id = "2147779169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "jkalsjdnaskdas!" ascii //weight: 20
        $x_20_2 = "sdfsdfsd" ascii //weight: 20
        $x_20_3 = "gdsfasdsa#" ascii //weight: 20
        $x_20_4 = "asfadfasdasdsa" ascii //weight: 20
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = "ToBase64String" ascii //weight: 1
        $x_1_7 = "IsLogging" ascii //weight: 1
        $x_1_8 = "tester" ascii //weight: 1
        $x_1_9 = "Decompress" ascii //weight: 1
        $x_1_10 = "Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 6 of ($x_1_*))) or
            ((3 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DB_2147779632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DB!MTB"
        threat_id = "2147779632"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "gsdfgsd" ascii //weight: 20
        $x_10_2 = "sdfsdfsdfsdfsdfsd" ascii //weight: 10
        $x_10_3 = "hdfhdfgdf" ascii //weight: 10
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "IsLogging" ascii //weight: 1
        $x_1_7 = "tester" ascii //weight: 1
        $x_1_8 = "Decompress" ascii //weight: 1
        $x_1_9 = "Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DC_2147779971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DC!MTB"
        threat_id = "2147779971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "86"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "jkalsjdnaskdas!" ascii //weight: 50
        $x_50_2 = "ygdsfsd2" ascii //weight: 50
        $x_20_3 = "ghfgrefvdvew2" ascii //weight: 20
        $x_20_4 = "sdgsdfs" ascii //weight: 20
        $x_3_5 = "IsDebuggerPresent" ascii //weight: 3
        $x_3_6 = "ToBase64String" ascii //weight: 3
        $x_3_7 = "tester" ascii //weight: 3
        $x_3_8 = "Decompress" ascii //weight: 3
        $x_3_9 = "Decrypt" ascii //weight: 3
        $x_1_10 = "IsLogging" ascii //weight: 1
        $x_1_11 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_20_*) and 5 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DD_2147780074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DD!MTB"
        threat_id = "2147780074"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "ghfgrefvdvew2" ascii //weight: 20
        $x_20_2 = "gfdgfdsdfsd" ascii //weight: 20
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "tester" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DE_2147780334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DE!MTB"
        threat_id = "2147780334"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "aksadkska" ascii //weight: 20
        $x_20_2 = "sdfsadsds" ascii //weight: 20
        $x_20_3 = "hdfghdfhdfgdfg" ascii //weight: 20
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "tester" ascii //weight: 1
        $x_1_7 = "Decompress" ascii //weight: 1
        $x_1_8 = "Decrypt" ascii //weight: 1
        $x_1_9 = "ReverseDecode" ascii //weight: 1
        $x_1_10 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DG_2147780443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DG!MTB"
        threat_id = "2147780443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fdsasasaa" ascii //weight: 1
        $x_1_2 = "ToBase64String" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "Decompress" ascii //weight: 1
        $x_1_5 = "Decrypt" ascii //weight: 1
        $x_1_6 = "ReverseDecode" ascii //weight: 1
        $x_1_7 = "DebuggingModes" ascii //weight: 1
        $x_1_8 = "Caramele" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ElysiumStealer_DH_2147780580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DH!MTB"
        threat_id = "2147780580"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "fghfghf" ascii //weight: 20
        $x_20_2 = "dfhdfgdf" ascii //weight: 20
        $x_20_3 = "FILEMY Company" ascii //weight: 20
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "tester" ascii //weight: 1
        $x_1_7 = "Decompress" ascii //weight: 1
        $x_1_8 = "Decrypt" ascii //weight: 1
        $x_1_9 = "ReverseDecode" ascii //weight: 1
        $x_1_10 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DJ_2147780655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DJ!MTB"
        threat_id = "2147780655"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "fsdfef421" ascii //weight: 20
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "ToBase64String" ascii //weight: 1
        $x_1_4 = "tester" ascii //weight: 1
        $x_1_5 = "Decompress" ascii //weight: 1
        $x_1_6 = "Decrypt" ascii //weight: 1
        $x_1_7 = "ReverseDecode" ascii //weight: 1
        $x_1_8 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ElysiumStealer_DK_2147780815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DK!MTB"
        threat_id = "2147780815"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "fghjfghf" ascii //weight: 20
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "ToBase64String" ascii //weight: 1
        $x_1_4 = "tester" ascii //weight: 1
        $x_1_5 = "Decompress" ascii //weight: 1
        $x_1_6 = "Decrypt" ascii //weight: 1
        $x_1_7 = "ReverseDecode" ascii //weight: 1
        $x_1_8 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ElysiumStealer_DL_2147781295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DL!MTB"
        threat_id = "2147781295"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "9318742" ascii //weight: 20
        $x_20_2 = "a5322222" ascii //weight: 20
        $x_1_3 = "_FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "tester" ascii //weight: 1
        $x_1_7 = "Decompress" ascii //weight: 1
        $x_1_8 = "Decrypt" ascii //weight: 1
        $x_1_9 = "ReverseDecode" ascii //weight: 1
        $x_1_10 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DM_2147781550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DM!MTB"
        threat_id = "2147781550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "4rfewfsa" ascii //weight: 20
        $x_1_2 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "tester" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ElysiumStealer_DN_2147781552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DN!MTB"
        threat_id = "2147781552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "asfasdasdw2" ascii //weight: 20
        $x_20_2 = "4rfewfsa" ascii //weight: 20
        $x_1_3 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "tester" ascii //weight: 1
        $x_1_7 = "Decompress" ascii //weight: 1
        $x_1_8 = "Decrypt" ascii //weight: 1
        $x_1_9 = "ReverseDecode" ascii //weight: 1
        $x_1_10 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DO_2147781674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DO!MTB"
        threat_id = "2147781674"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "plication reserved" ascii //weight: 20
        $x_20_2 = "hfddfvfsdce222" ascii //weight: 20
        $x_1_3 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "tester" ascii //weight: 1
        $x_1_7 = "Decompress" ascii //weight: 1
        $x_1_8 = "Decrypt" ascii //weight: 1
        $x_1_9 = "ReverseDecode" ascii //weight: 1
        $x_1_10 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DP_2147781828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DP!MTB"
        threat_id = "2147781828"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "sdgsdfe31w" ascii //weight: 20
        $x_1_2 = "ToBase64String" ascii //weight: 1
        $x_1_3 = "IsLogging" ascii //weight: 1
        $x_1_4 = "Decompress" ascii //weight: 1
        $x_1_5 = "Decrypt" ascii //weight: 1
        $x_1_6 = "ReverseDecode" ascii //weight: 1
        $x_1_7 = "Resolve" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ElysiumStealer_DQ_2147781864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DQ!MTB"
        threat_id = "2147781864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "gdfgdf221s" ascii //weight: 20
        $x_1_2 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "tester" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DR_2147781865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DR!MTB"
        threat_id = "2147781865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "gdffdsgdf221s" ascii //weight: 20
        $x_1_2 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "tester" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DS_2147782066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DS!MTB"
        threat_id = "2147782066"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "HoldRuftSft" ascii //weight: 20
        $x_1_2 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "tester" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DT_2147782198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DT!MTB"
        threat_id = "2147782198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "iFEODHDQ1" ascii //weight: 20
        $x_1_2 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "tester" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DU_2147782464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DU!MTB"
        threat_id = "2147782464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "sgfdsgfdgjp" ascii //weight: 20
        $x_1_2 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "tester" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DV_2147782669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DV!MTB"
        threat_id = "2147782669"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "fghfgh" ascii //weight: 20
        $x_1_2 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "tester" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DW_2147782671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DW!MTB"
        threat_id = "2147782671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "dfsdfdsfd" ascii //weight: 20
        $x_1_2 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "tester" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DX_2147782974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DX!MTB"
        threat_id = "2147782974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "ppoopopo" ascii //weight: 20
        $x_1_2 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "tester" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DY_2147783082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DY!MTB"
        threat_id = "2147783082"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "erytrewr" ascii //weight: 20
        $x_20_2 = "dfgsdfsdfs" ascii //weight: 20
        $x_1_3 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "tester" ascii //weight: 1
        $x_1_7 = "Decompress" ascii //weight: 1
        $x_1_8 = "Decrypt" ascii //weight: 1
        $x_1_9 = "ReverseDecode" ascii //weight: 1
        $x_1_10 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_DZ_2147783202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.DZ!MTB"
        threat_id = "2147783202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "NewBrowserSoft" ascii //weight: 20
        $x_1_2 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "tester" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_EA_2147783312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.EA!MTB"
        threat_id = "2147783312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "gfhfghfg" ascii //weight: 20
        $x_20_2 = "dstgstgsdfds" ascii //weight: 20
        $x_1_3 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "tester" ascii //weight: 1
        $x_1_7 = "Decompress" ascii //weight: 1
        $x_1_8 = "Decrypt" ascii //weight: 1
        $x_1_9 = "ReverseDecode" ascii //weight: 1
        $x_1_10 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_EB_2147783694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.EB!MTB"
        threat_id = "2147783694"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "dwsgsdffsd" ascii //weight: 20
        $x_1_2 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "tester" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_EC_2147783749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.EC!MTB"
        threat_id = "2147783749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "dfghdfgfd" ascii //weight: 20
        $x_20_2 = "oipooip" ascii //weight: 20
        $x_1_3 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "tester" ascii //weight: 1
        $x_1_7 = "Decompress" ascii //weight: 1
        $x_1_8 = "Decrypt" ascii //weight: 1
        $x_1_9 = "ReverseDecode" ascii //weight: 1
        $x_1_10 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_ED_2147783877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.ED!MTB"
        threat_id = "2147783877"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "fgdfdfdsgf" ascii //weight: 20
        $x_1_2 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "tester" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_EE_2147783878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.EE!MTB"
        threat_id = "2147783878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "fgfghgfgfhghf" ascii //weight: 20
        $x_1_2 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "tester" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_EG_2147788237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.EG!MTB"
        threat_id = "2147788237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "asdfasdasf" ascii //weight: 20
        $x_20_2 = "jhgfjhgf" ascii //weight: 20
        $x_20_3 = "yutyuuyytu" ascii //weight: 20
        $x_10_4 = "SFDSDFSD!!!" ascii //weight: 10
        $x_1_5 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_7 = "ToBase64String" ascii //weight: 1
        $x_1_8 = "tester" ascii //weight: 1
        $x_1_9 = "Decompress" ascii //weight: 1
        $x_1_10 = "Decrypt" ascii //weight: 1
        $x_1_11 = "ReverseDecode" ascii //weight: 1
        $x_1_12 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_EF_2147788431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.EF!MTB"
        threat_id = "2147788431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "fgfdgdfgdgf" ascii //weight: 20
        $x_20_2 = "hdfgdfgdfgdf" ascii //weight: 20
        $x_20_3 = "dfvcgfdgdf" ascii //weight: 20
        $x_20_4 = "hghgjhgfdghfd" ascii //weight: 20
        $x_10_5 = "SFDSDFSD!!!" ascii //weight: 10
        $x_1_6 = "FILETYPE_FILE_ICON_1877" ascii //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_8 = "ToBase64String" ascii //weight: 1
        $x_1_9 = "tester" ascii //weight: 1
        $x_1_10 = "Decompress" ascii //weight: 1
        $x_1_11 = "Decrypt" ascii //weight: 1
        $x_1_12 = "ReverseDecode" ascii //weight: 1
        $x_1_13 = "eshelon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_EH_2147793312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.EH!MTB"
        threat_id = "2147793312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "dddddsssdas.exe" ascii //weight: 20
        $x_20_2 = "ddddddas.exe" ascii //weight: 20
        $x_20_3 = "dfghdfggdfgdf" ascii //weight: 20
        $x_1_4 = "ToBase64String" ascii //weight: 1
        $x_1_5 = "get_CurrentDomain" ascii //weight: 1
        $x_1_6 = "Decompress" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "ReverseDecode" ascii //weight: 1
        $x_1_9 = "LzmaDecoder" ascii //weight: 1
        $x_1_10 = "Resolve" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_EI_2147793873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.EI!MTB"
        threat_id = "2147793873"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "fdsfsfdfsd" ascii //weight: 20
        $x_20_2 = "fafasdsad" ascii //weight: 20
        $x_20_3 = "csdcsddssd" ascii //weight: 20
        $x_20_4 = "fsfdfdsfs" ascii //weight: 20
        $x_20_5 = "bvsdvdssd" ascii //weight: 20
        $x_20_6 = "gdfgdfgdfg" ascii //weight: 20
        $x_1_7 = "ToBase64String" ascii //weight: 1
        $x_1_8 = "get_CurrentDomain" ascii //weight: 1
        $x_1_9 = "Decompress" ascii //weight: 1
        $x_1_10 = "Decrypt" ascii //weight: 1
        $x_1_11 = "ReverseDecode" ascii //weight: 1
        $x_1_12 = "LzmaDecoder" ascii //weight: 1
        $x_1_13 = "Resolve" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 7 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_EJ_2147793875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.EJ!MTB"
        threat_id = "2147793875"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "dfghdfggdfgdf" ascii //weight: 20
        $x_20_2 = "fafasdsad" ascii //weight: 20
        $x_1_3 = "ddddddas" ascii //weight: 1
        $x_1_4 = "asdasda" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "get_CurrentDomain" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "GetTypes" ascii //weight: 1
        $x_1_10 = "Convert" ascii //weight: 1
        $x_1_11 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 9 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_ElysiumStealer_EK_2147793876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ElysiumStealer.EK!MTB"
        threat_id = "2147793876"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ElysiumStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "67"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "adsasdasa" ascii //weight: 50
        $x_50_2 = "bfdfbdfbdfbdfbdfbdf" ascii //weight: 50
        $x_50_3 = "dsffdsfsdfs" ascii //weight: 50
        $x_10_4 = "ppphhyf" ascii //weight: 10
        $x_10_5 = "gfgfdfdg" ascii //weight: 10
        $x_1_6 = "ToBase64String" ascii //weight: 1
        $x_1_7 = "get_CurrentDomain" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "DebuggingModes" ascii //weight: 1
        $x_1_10 = "GetTypes" ascii //weight: 1
        $x_1_11 = "Convert" ascii //weight: 1
        $x_1_12 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_10_*) and 7 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_10_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

