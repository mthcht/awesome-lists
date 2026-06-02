rule Trojan_PowerShell_PowDow_DD_2147961564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/PowDow.DD!MTB"
        threat_id = "2147961564"
        type = "Trojan"
        platform = "PowerShell: "
        family = "PowDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = "$env:" wide //weight: 1
        $x_1_3 = ".(gal *ex)(&(gcm *estM*)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

