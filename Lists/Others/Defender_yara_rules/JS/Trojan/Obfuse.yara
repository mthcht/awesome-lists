rule Trojan_JS_Obfuse_NF_2147969945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:JS/Obfuse.NF!MTB"
        threat_id = "2147969945"
        type = "Trojan"
        platform = "JS: JavaScript scripts"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "71"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "powershell" wide //weight: 50
        $x_10_2 = "$env:INTERNAL_DB_CACHE" wide //weight: 10
        $x_10_3 = "SetEnvironmentVariable('INTERNAL_DB_CACHE',$null,'User')" wide //weight: 10
        $x_1_4 = "Bypass" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

