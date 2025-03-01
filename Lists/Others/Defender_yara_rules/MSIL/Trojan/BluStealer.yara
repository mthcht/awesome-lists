rule Trojan_MSIL_BluStealer_NX_2147828209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BluStealer.NX!MTB"
        threat_id = "2147828209"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BluStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 13 05 08 13 06 11 05 11 06 3d ?? ?? ?? 00 72 ?? ?? ?? 70 02 09 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 03 11 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 61 69 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 07 06 11 07 6f ?? ?? ?? 0a 26 11 04 03 6f ?? ?? ?? 0a 17 59 40 ?? ?? ?? 00 16 13 04 38 ?? ?? ?? 00 11 04 17 58 13 04 09 18 58 0d 2b 92}  //weight: 10, accuracy: Low
        $x_1_2 = "ToBase64String" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BluStealer_QH_2147828799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BluStealer.QH!MTB"
        threat_id = "2147828799"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BluStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 13 05 08 13 06 11 05 11 06 3d ?? ?? ?? 00 72 ?? ?? ?? 70 02 09 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 03 11 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 61 69 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 07 06 11 07 6f ?? ?? ?? 0a 26 11 04 03}  //weight: 10, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = ".lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BluStealer_RDA_2147833882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BluStealer.RDA!MTB"
        threat_id = "2147833882"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BluStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 07 08 09 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 00 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 00 7e ?? ?? ?? ?? 06 28 ?? ?? ?? ?? d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04}  //weight: 2, accuracy: Low
        $x_1_2 = "uG.B1" wide //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
        $x_1_4 = "GetMethod" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
        $x_1_6 = "GetDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BluStealer_A_2147837084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BluStealer.A!MTB"
        threat_id = "2147837084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BluStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 25 16 1f 2d 9d 6f 06 00 00 00 0a 17 8d}  //weight: 2, accuracy: Low
        $x_2_2 = {07 06 11 08 9a 1f 10 28 ?? 00 00 0a 8c ?? 00 00 01 6f ?? 00 00 0a 26 11 08 17 58 13 08 11 08 06 8e 69}  //weight: 2, accuracy: Low
        $x_2_3 = {00 00 01 25 16 1f 25 9d 6f 22 00 00 0a 06 00 00 00 04 17 8d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BluStealer_FAI_2147845047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BluStealer.FAI!MTB"
        threat_id = "2147845047"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BluStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 11 04 8e 69 17 da 13 06 16 13 07 2b 28 11 05 11 04 11 07 9a 28 ?? 00 00 0a 23 00 00 00 00 00 20 7e 40 59 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 07 17 d6 13 07 11 07 11 06 31 d2}  //weight: 2, accuracy: Low
        $x_1_2 = "pastebin.pl/view/raw/fa15aeff" wide //weight: 1
        $x_1_3 = "insert bitcoin block hash:" wide //weight: 1
        $x_1_4 = "Wallet info request - insert bitcoin wallet address" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

