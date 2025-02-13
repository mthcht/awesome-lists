rule Trojan_MSIL_BlitzedGrabber_CXLM_2147850027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BlitzedGrabber.CXLM!MTB"
        threat_id = "2147850027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlitzedGrabber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "**BLITZED GRABBER" wide //weight: 1
        $x_1_2 = "Main Stealing" wide //weight: 1
        $x_1_3 = "Tokens.txt" wide //weight: 1
        $x_1_4 = "Passwords" wide //weight: 1
        $x_1_5 = "Credit Cards" wide //weight: 1
        $x_1_6 = "WIFI Password" wide //weight: 1
        $x_1_7 = "Gaming Accounts" wide //weight: 1
        $x_1_8 = "Minecraft" wide //weight: 1
        $x_1_9 = "Steam" wide //weight: 1
        $x_1_10 = "bitcoin" wide //weight: 1
        $x_1_11 = "monero" wide //weight: 1
        $x_1_12 = "etherium" wide //weight: 1
        $x_1_13 = "stellarcoin" wide //weight: 1
        $x_1_14 = "blockchain" wide //weight: 1
        $x_1_15 = "Amex Card" wide //weight: 1
        $x_1_16 = "BCGlobal" wide //weight: 1
        $x_1_17 = "Diners Club Card" wide //weight: 1
        $x_1_18 = "\\Opera Software\\Opera Stable" wide //weight: 1
        $x_1_19 = "\\Google\\Chrome\\User Data\\Default" wide //weight: 1
        $x_1_20 = "\\Local Storage\\leveldb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

