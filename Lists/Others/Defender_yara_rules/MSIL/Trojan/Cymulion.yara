rule Trojan_MSIL_Cymulion_SN_2147975027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cymulion.SN!MTB"
        threat_id = "2147975027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cymulion"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$9ea51d40-94dc-44cd-8934-cc58960b2fdc" ascii //weight: 2
        $x_1_2 = "bitsadmin.exe //transfer " wide //weight: 1
        $x_1_3 = "certutil.exe -urlcache -split -f " wide //weight: 1
        $x_1_4 = "Powershell.exe -noprofile -windowstyle hidden -ep Bypass -file " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

