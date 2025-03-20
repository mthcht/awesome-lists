rule Trojan_PowerShell_DownInfo_A_2147933994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/DownInfo.A"
        threat_id = "2147933994"
        type = "Trojan"
        platform = "PowerShell: "
        family = "DownInfo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "invoke-webrequest -uri \"$api/script?machineid=$guid\"" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_DownInfo_B_2147933995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/DownInfo.B"
        threat_id = "2147933995"
        type = "Trojan"
        platform = "PowerShell: "
        family = "DownInfo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "chromeuseragentupdater" wide //weight: 10
        $x_10_2 = "microsoftversionagent" wide //weight: 10
        $x_10_3 = "windowssoftwareupdater" wide //weight: 10
        $x_10_4 = "versionupdaterlegacy" wide //weight: 10
        $x_10_5 = "systemhealthcheckerlegacy" wide //weight: 10
        $x_10_6 = "get-registryvalue \"hklm:\\software\\microsoft\\cryptography\" \"machineguid\"" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_PowerShell_DownInfo_C_2147933996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/DownInfo.C"
        threat_id = "2147933996"
        type = "Trojan"
        platform = "PowerShell: "
        family = "DownInfo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 00 70 00 73 00 68 00 6f 00 6d 00 65 00 5b 00 [0-4] 5d 00 2b 00 24 00 70 00 73 00 68 00 6f 00 6d 00 65 00 5b 00 [0-4] 5d 00 2b 00 27 00 78 00 27 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

