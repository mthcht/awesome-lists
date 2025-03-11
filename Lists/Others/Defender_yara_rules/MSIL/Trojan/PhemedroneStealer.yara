rule Trojan_MSIL_PhemedroneStealer_CB_2147850817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhemedroneStealer.CB!MTB"
        threat_id = "2147850817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhemedroneStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c 00 00 fe 0c 02 00 91 fe 0e 03 00 7e ?? ?? ?? ?? fe 0c 02 00 7e ?? ?? ?? ?? 6f 6e 00 00 0a 5d 6f 1a 01 00 0a fe 0e 04 00 fe 0c 03 00 fe 0c 04 00 61 d1 fe 0e}  //weight: 1, accuracy: Low
        $x_1_2 = {05 00 fe 0c 01 00 fe 0c 05 00 6f 93 01 00 0a 26 00 fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 0c 00 00 8e 69 fe 04 fe 0e 06 00 fe 0c 06 00 2d 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PhemedroneStealer_CC_2147850818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhemedroneStealer.CC!MTB"
        threat_id = "2147850818"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhemedroneStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Phemedrone Stealer" wide //weight: 1
        $x_1_2 = "BestStealer" wide //weight: 1
        $x_1_3 = "wallet.dat" wide //weight: 1
        $x_1_4 = "Electrum\\wallets" wide //weight: 1
        $x_1_5 = "Browser Data/Cookies" wide //weight: 1
        $x_1_6 = "CreditCards.txt" wide //weight: 1
        $x_1_7 = "Antivirus products" wide //weight: 1
        $x_1_8 = "VirtualBox" wide //weight: 1
        $x_1_9 = "VMware" wide //weight: 1
        $x_1_10 = "Password.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PhemedroneStealer_NIT_2147931113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhemedroneStealer.NIT!MTB"
        threat_id = "2147931113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhemedroneStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GeckoBrowsersList" ascii //weight: 2
        $x_2_2 = "GetMozillaBrowsers" ascii //weight: 2
        $x_2_3 = "ProgramFilesChildren" ascii //weight: 2
        $x_2_4 = "GetMozillaPath" ascii //weight: 2
        $x_1_5 = "set_sUrl" ascii //weight: 1
        $x_1_6 = "vmware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_PhemedroneStealer_SWA_2147935623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhemedroneStealer.SWA!MTB"
        threat_id = "2147935623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhemedroneStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 02 00 00 2b 7e 29 00 00 04 25 2d 17 26 7e 28 00 00 04 fe 06 5e 00 00 06 73 6c 00 00 0a 25 80 29 00 00 04 28 03 00 00 2b 7e 2a 00 00 04 25 2d 17 26 7e 28 00 00 04 fe 06 5f 00 00 06 73 6e 00 00 0a 25 80 2a 00 00 04 28 04 00 00 2b 28 05 00 00 2b 08 fe 06 64 00 00 06 73 71 00 00 0a 6f 72 00 00 0a 28 66 00 00 06 08 7b 2e 00 00 04 28 75 00 00 06 de 14 08 7b 2e 00 00 04 2c 0b 08 7b 2e 00 00 04 6f 01 00 00 0a dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

