rule Trojan_MSIL_OsirisLoader_PAA_2147775608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OsirisLoader.PAA!MTB"
        threat_id = "2147775608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OsirisLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "', 'User').split();$p=$r[0];$r[0]='';Start-Process $p -ArgumentList ($r -join ' ') -Win Hi\"" wide //weight: 1
        $x_1_2 = "powershell -Win Hi -Command \"$r = [Environment]::GetEnvironmentVariable('" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
        $x_1_4 = ".exe -windowstyle hidden" wide //weight: 1
        $x_1_5 = "get_UserName" ascii //weight: 1
        $x_1_6 = "windowstyle" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

